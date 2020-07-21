const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    title: { type: String, required: true },
    photo: { type: String, required: true },
    description: { type: String, required: true },
});


module.exports = mongoose.model('Book', schema);