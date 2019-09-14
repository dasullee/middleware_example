const express = require('express');
const PORT = process.env.PORT || 9000;
const auth = require('./middleware/auth');

const app = express();

app.get('/api/articles', auth([1,2]), (req, res) => {
    
    const articles = [
        {
            title: 'All about Cats',
            content: 'Lorem ipsum dolor, sit amet consectetur adipisicing elit. Odio doloremque ducimus officiis eaque, quam dolor ad repellendus obcaecati numquam voluptates magni quo explicabo repudiandae nulla molestias recusandae officia magnam dolorem?'
        },
        {
            title: 'All about Dogs',
            content: 'Lorem ipsum dolor sit amet consectetur adipisicing elit. Laudantium mollitia possimus amet minus id officia unde, ea reiciendis, maiores fuga non. Similique sed vel necessitatibus praesentium laudantium minima suscipit provident.'
        },
        {
            title: 'All about foxes',
            content: 'Lorem ipsum dolor sit amet consectetur adipisicing elit. Doloremque fugit voluptate qui, molestias recusandae architecto voluptatum ab quibusdam ea minus molestiae! Veniam, minus molestias. Voluptatem facere alias autem ex ab!'
        }
    ];

    res.send(articles);
});

app.get('/api/users', auth([2]), (req, res) => {


    const users = [
        {
            name: "Karen Freelander",
            email: "karen@example.com"
        },
        {
            name: "Jim Kirk",
            email: "jim@example.com"
        },
        {
            name: "Tony Stark",
            email: "tony@example.com"
        },
        {
            name: "Nancy Smith",
            email: "nancy@example.com"
        }
    ];
    res.send(users);
});

app.get('/api/profile', auth, async (req, res) => {
    res.send(req.user);
});

app.listen(PORT, () => {
    console.log('Server listening @ localhost:' + PORT);
});

