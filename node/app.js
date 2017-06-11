/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request'),
  apiai = require('apiai');

var apiai_app = apiai("e04a7358ee1a474d846d05fd679b7a8c");
var app = express();
app.set('port', 1882);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

      sendToApiAi(senderID, quickReplyPayload);
      
    return;
  }

  if (messageText) {

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText) {
      // case 'image':
      //   sendImageMessage(senderID);
      //   break;

      // case 'gif':
      //   sendGifMessage(senderID);
      //   break;

      // case 'audio':
      //   sendAudioMessage(senderID);
      //   break;

      // case 'video':
      //   sendVideoMessage(senderID);
      //   break;

      // case 'file':
      //   sendFileMessage(senderID);
      //   break;

      // case 'button':
      //   sendButtonMessage(senderID);
      //   break;

      // case 'generic':
      //   sendGenericMessage(senderID);
      //   break;

      // case 'receipt':
      //   sendReceiptMessage(senderID);
      //   break;

      // case 'quick reply':
      //   sendQuickReply(senderID);
      //   break;        

      // case 'read receipt':
      //   sendReadReceipt(senderID);
      //   break;        

      // case 'typing on':
      //   sendTypingOn(senderID);
      //   break;        

      // case 'typing off':
      //   sendTypingOff(senderID);
      //   break;        

      // case 'account linking':
      //   sendAccountLinking(senderID);
      //   break;

      default:
        if (!database.users[senderID]) {
          getUser(senderID, function(user) {
            updateParams(senderID, {
              'user-name': user['first_name']
            });

            sendToApiAi(senderID, messageText);
          })
          
        } else {
          sendToApiAi(senderID, messageText);
        }
    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "Message with attachment received");
  }
}

function sendToApiAi(senderID, messageText) {
  sendTypingOn(senderID);

  var parameters = database.users[senderID]
  console.log(senderID, messageText, parameters);
  var request = apiai_app.textRequest(messageText, {
      "sessionId": senderID,
      "contexts": [
        {
          "name": "facebook",
          "parameters": parameters
        }
      ]
  });

  request.on('response', function(response) {
      console.log(senderID, response);
      updateParams(senderID, response.result.parameters);
      sendApiAiMessages(senderID, response.result.fulfillment.messages);
      sendTypingOff(senderID);
  });

  request.on('error', function(error) {
      console.error(error);
  });

  request.end();
}

function sendGroupsList(user_id, user_props)  {
  console.log("Final params for ", user_id, user_props);
  var groups = database.groups.filter((x) => {
      if (user_props['job']) {
        if (x.jobs.indexOf(user_props['job']) == -1) {
          return false;
        }
      } 
      
      if (user_props['grade']) {
        if (x.min_grade > parseInt(user_props['grade'])) {
          return false;
        }
      }

      if (user_props['subject']) {
        if (x.subjects.indexOf(user_props['subject']) == -1) {
          return false;
        }
      }

      return true;

    }).sort(
      (a, b) => {
        return a.min_grade < b.min_grade;
      }
    )
    .map((x) => {
      return {
        "title": x.title,
        "default_action": {
          "type": "web_url",
          "url": "https://www.facebook.com/groups/" + x.group,
          "webview_height_ratio": "tall"
        },
        "image_url": x.image_url,
        "subtitle": "For: " + x.jobs.map((y) => {
          return y.charAt(0).toUpperCase() + y.slice(1);
        }).join(", ")
      };
    }).slice(0, 5);

  if (groups.length > 0) {
    sendTextMessage(user_id, "I think you might like to join these groups: ");
    sendGenericMessage(user_id, groups);
    delete database.users[user_id];
  } else {
    sendTextMessage(user_id, "I can't find any active groups that match your profile...");
  }
}

function sendApiAiMessages(user_id, messages) {
  console.log("Messages: ", JSON.stringify(messages));
  var isSent = false;

  var imageMessages = messages.filter((x) => x.type == 3);

  for (var i in imageMessages) {
    var message = imageMessages[i];
    sendImageMessage(user_id, message.imageUrl);
  }

  var textMessages = messages.filter((x) => x.type == 0);

  if (textMessages.length > 0 && textMessages[0].speech.length > 0) {
    sendTextMessage(user_id, textMessages[0].speech);
  }

  var quickReplies = messages.filter((x) => x.type == 2);

  for (var i in quickReplies) {
    var message = quickReplies[i];
    sendQuickReply(user_id, message.title, message.replies);
  }

  var customMessages = messages.filter((x) => x.type == 4);

  if (customMessages.length > 0) {
    var message = customMessages[0];
    processCustom(user_id, message);
  }

}

function processCustom(user_id, message) {
  console.log("Custom", message.payload);
  switch(message.payload.intent) {
    case "find_groups":
        var user = database.users[user_id];
        
        setTimeout(function() {
          sendTypingOn(user_id);
          setTimeout(function() {
            sendTypingOff(user_id);
            sendGroupsList(user_id, {
              'age': user['user-age']['amount'], 
              'subject': user['subject-availability'], 
              'grade': user['user-grade'],
              'job': user['user-aspiration']
            });
          }, 1000);
        }, 1000);
        
      break;
    default: 
      console.log("Invalid intent: ", message.payload);
  }
}

var database = {
  users: [],
  groups: [
    {
      image_url: SERVER_URL + "/assets/English1.png",
      title: "English Grammar, We welcome all!",
      jobs: ["writer", "educator"],
      subjects: ["English"],
      min_grade: 1,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/English2.png",
      title: "Speaking English, the global language",
      jobs: ["writer", "educator", "social work"],
      subjects: ["English"],
      min_grade: 6,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/English3.png",
      title: "English Vocabulary",
      jobs: ["writer", "educator"],
      subjects: ["English"],
      min_grade: 5,
      group: "1970897529862706" // CORRECT
    },
    {
      image_url: SERVER_URL + "/assets/English4.jpg",
      title: "Business English: Guidance on formal emails and workplace discussions.",
      jobs: ["writer", "educator", "social work"],
      subjects: ["English"],
      min_grade: 6,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/English5.png",
      title: "Learn how to write and speak English properly!",
      jobs: ["writer", "educator", "social work", "computer scientist", "engineer"],
      subjects: ["English"],
      min_grade: 2,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Math1.png",
      title: "Mental Sums: Learn how to develop effective counting methods",
      jobs: ["educator", "engineer", "computer scientist"],
      subjects: ["Math"],
      min_grade: 2,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Math2.png",
      title: "Logic is fun! Join us for classes on math and problem solving using puzzles.",
      jobs: ["educator", "engineer", "computer scientist"],
      subjects: ["Math"],
      min_grade: 3,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Math3.jpg",
      title: "Textbook math! We are here to tell you more about what math impacts the world!",
      jobs: ["educator", "engineer", "computer scientist", "social work"],
      subjects: ["Math"],
      min_grade: 4,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Math4.jpg",
      title: "Basic algebra, the math that build our world today.",
      jobs: ["educator", "engineer", "computer scientist"],
      subjects: ["Math"],
      min_grade: 3,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Math5.jpg",
      title: "Mathemagic, Learn the coolest ways you can use math to have fun",
      jobs: ["educator", "engineer", "computer scientist", "social work"],
      subjects: ["Math"],
      min_grade: 1,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Programming1.png",
      title: "Python: Coding the future",
      jobs: ["engineer", "computer scientist"],
      subjects: ["Programming"],
      min_grade: 7,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Programming2.png",
      title: "How you can build your own system and a presence in the World Wide Map",
      jobs: ["engineer", "computer scientist", "social work"],
      subjects: ["Programming"],
      min_grade: 8,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Programming3.png",
      title: "Connect the world with your own mobile application!",
      jobs: ["engineer", "computer scientist"],
      subjects: ["Programming"],
      min_grade: 6,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Programming4.png",
      title: "Scratch: The foundation you need to be a programmer",
      jobs: ["engineer", "computer scientist"],
      subjects: ["Programming"],
      min_grade: 3,
      group: "1970897529862706"
    },
    {
      image_url: SERVER_URL + "/assets/Programming5.png",
      title: "Ruby on Rails: The web application builder that is used worldwide",
      jobs: ["engineer", "computer scientist"],
      subjects: ["Programming"],
      min_grade: 5,
      group: "1970897529862706"
    }
  ]
}

function updateParams(user_id, parameters) {
  if (!database.users[user_id]) {
    database.users[user_id] = {};
  }

  for (var key in parameters) {
    database.users[user_id][key] = parameters[key];
  }
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to 
  // let them know it was successful
  if (payload.indexOf("JOIN_GROUP") == 0) {
    sendTextMessage(senderID, "Let me invite you to the group!");
    var group = payload.split(",")[1];
    request({
      uri: 'https://graph.facebook.com/v2.9/' + group + "/members",
      qs: { access_token: PAGE_ACCESS_TOKEN },
      method: 'POST',
      formData: {
        "member": senderID
      }
    }, function (error, response, body) {
      console.log(body);
      if (!error && response.statusCode == 200) {
        console.log("Sent invite", body);
      } else {
        console.error("Failed sending invite.", response.statusCode, response.statusMessage, body.error);
      }
    }); 
  } else {
    sendTextMessage(senderID, "Postback called");
  }
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId, image_url) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: image_url
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "/assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a file using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "/assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPER_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId, elements) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: elements
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",        
          timestamp: "1428444852", 
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId, title, replies) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: title,
      quick_replies: replies.map((x) => {
        return {
          "content_type": "text",
          "title": x,
          "payload": x
        }
      })
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

function getUser(user_id, callback) {
   request({
    uri: 'https://graph.facebook.com/v2.6/' + user_id,
    qs: { fields: "first_name,last_name,profile_pic,locale,timezone,gender", access_token: PAGE_ACCESS_TOKEN },
    method: 'GET'
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      callback(JSON.parse(body));
    } else {
      console.error("Failed getting user profile", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;

