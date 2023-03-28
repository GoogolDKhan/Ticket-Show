# Ticket Show Application

This is a web application built using Flask framework, Jinja2 templates and Bootstrap for HTML generation and styling, and SQLite for data storage.

The Ticket Show Application is a multi-user app that allows users to book show tickets. It has an admin login and other user login for different functionalities.

Terminology

- Venue: A location where shows can be hosted
- Show: An event that can be hosted at a venue

## Core Features

### Admin and User Login

The application has separate login forms for users and admin. The user needs to enter a valid username and password to access the application, while the admin needs to use an admin login form to access the admin dashboard.

### Venue Management

The admin can create a new venue, edit an existing venue, or remove a venue from the application. Each venue has a unique ID, Name, Place, and Capacity, which can be updated through the admin dashboard.

### Show Management

The admin can create a new show, edit an existing show, or remove a show from the application. Each show has a unique ID, Name, Rating, Tags, TicketPrice, and Venue ID.

### Search for Shows/Venues

The application allows users to search for shows and venues based on location preferences, tags, ratings, etc.

### Book Show Tickets

The application allows users to book multiple tickets for a show at a given venue. The application also prevents booking once a show is houseful.

## Usage

No need when using replit.

```sh
pip install -r requirements.txt
```
