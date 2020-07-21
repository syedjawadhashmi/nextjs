const db = require('_helpers/db');

module.exports = {
    getBook,
    getPrivateBook
};

async function getBook() {
    const books = await db.Book.find();
    return books.map(x => basicDetails(x));
}

async function getPrivateBook() {
    const books = await db.Book.find();
    return books.map(x => basicDetails(x));
}

function basicDetails(books) {
    const { title, photo, description } = books;
    return { title, photo, description };
}