const express = require('express');
const router = express.Router();
const bookService = require('./book.service');
const authorize = require('_middleware/authorize')

// routes
router.get('/', getBook);
router.get('/privateBooks', authorize(), getPrivateBook);

module.exports = router;

function getBook(req, res, next) {
    bookService.getBook()
        .then(books => res.json(books))
        .catch(next);
}

function getPrivateBook(req, res, next) {
    bookService.getBook()
        .then(books => res.json(books))
        .catch(next);
}
