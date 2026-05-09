const Joi = require("joi");

const emailModel = Joi.object({
  metadata: Joi.object({
    fromEmail: Joi.string().email().required(), //האם זה אימייל?
    replyTo: Joi.string().email().allow("", null),
    subject: Joi.string().max(500).required(),
    authResults: Joi.string().max(5000).allow("", null),
    messageId: Joi.string().max(500).allow("", null),
  }).required(),

  content: Joi.object({
    bodyText: Joi.string().max(200000).required(),
    links: Joi.array()
      .max(200)
      .items(
        Joi.object({
          displayText: Joi.string().max(2000).allow("", null),
          url: Joi.string().max(2000).required(),
        }),
      ),
    attachments: Joi.array()
      .max(20)
      .items(
        Joi.object({
          filename: Joi.string().max(255).required(),
          mimeType: Joi.string().max(255).required(),
          size: Joi.number().max(25000000),
        }),
      ),
  }).required(),
}).options({ allowUnknown: false }); // אם הלקוח ניסה לשלוח שדה שלא צריך לקבל חוסמים אוטומטית את הבקשה.

module.exports = emailModel;
