# PlanitApp: Application Documentation

## Overview

**PlanitApp** is a Django-based web application that integrates with Google services to provide seamless authentication and event management for users. The application leverages Django’s robust class-based views, authentication system, and ORM, while also demonstrating advanced integration with third-party APIs (Google OAuth2, Google Drive, Google Sheets).

---

## Key Features

### 1. Google OAuth2 Authentication

- **Django Class-Based Views**: Authentication flows are encapsulated in class-based views (`GoogleLogin`, `GoogleAuth`), promoting modularity and reusability.
- **Custom Social Token Model**: The app uses a custom `SocialToken` model to store OAuth tokens and user profile data, demonstrating Django ORM proficiency.
- **Atomic Transactions**: User creation and token storage are wrapped in atomic transactions, ensuring data integrity.
- **Secure Token Handling**: The app securely exchanges authorization codes for tokens, decodes JWTs using Google’s public keys, and validates user identity.

### 2. User Session Management

- **Django Authentication Integration**: Authenticated users are logged in using Django’s built-in `login()` function, ensuring compatibility with Django’s session middleware.
- **LoginRequiredMixin**: Views such as `HomePage` and `ShowCalendarEvents` are protected using `LoginRequiredMixin`, enforcing access control and redirecting unauthenticated users.

### 3. Event Management via Google Sheets

- **Google API Integration**: The app interacts with Google Drive and Sheets APIs to fetch and display user events.
- **Dynamic Spreadsheet Discovery**: Utilizes Google Drive API to locate user-specific spreadsheets by name.
- **Data Pagination**: Implements Django’s `Paginator` to efficiently paginate event data, enhancing scalability and user experience.
- **Timezone-Aware Datetimes**: Event datetimes are parsed and handled using Python’s `datetime` module, ensuring correct display and manipulation.

### 4. User Experience and Feedback

- **Django Messages Framework**: Success and error messages are communicated to users via Django’s messages framework.
- **Profile Picture Display**: User profile images are fetched from Google and displayed on the homepage and event pages.

### 5. Logging and Error Handling

- **Custom Loggers**: The application defines multiple loggers (`create_event_logger`, `show_event_logger`, `general_logger`) for granular monitoring and debugging.
- **Graceful Error Handling**: Uses try-except blocks and user-friendly error messages to handle API failures and missing data.

---

## Django Concepts Highlighted

### Class-Based Views (CBVs)

- The use of CBVs (`View`, `LoginRequiredMixin`) demonstrates a modern, scalable approach to request handling, promoting code reuse and separation of concerns.

### ORM and Transactions

- The application showcases advanced ORM usage with `get_or_create`, and ensures atomicity with `@transaction.atomic` decorators.

### Middleware and Authentication

- Seamless integration with Django’s authentication and session middleware ensures secure, stateful user experiences.

### Third-Party API Integration

- The code demonstrates best practices for integrating external APIs within Django, including secure credential management and token refresh logic.

### Template Rendering and Context Management

- Context dictionaries are constructed and passed to templates, following Django’s MVC (Model-View-Controller) paradigm.

---

## Technical Architecture

### File Structure

- `views.py`: Contains all view logic, including authentication, event retrieval, and homepage rendering.
- `models.py`: Defines the `SocialToken` model for storing OAuth tokens and user profile data.
- `templates/`: Contains Django templates for rendering the homepage and events.
- `settings.py`: Stores configuration for Google API credentials and scopes.

### Security Practices

- **Environment Variables**: Sensitive credentials are loaded from environment variables using `python-dotenv`.
- **Token Validation**: JWTs are validated against Google’s public keys, ensuring authenticity.
- **Access Control**: All sensitive views are protected by authentication checks.

---

## Recruiter-Focused Highlights

- **Modern Django Patterns**: The application leverages class-based views, mixins, and the ORM for clean, maintainable code.
- **API Integration**: Demonstrates advanced skills in integrating with OAuth2 and Google APIs.
- **Security and Best Practices**: Shows attention to security, error handling, and user experience.
- **Scalability**: Implements pagination and efficient data retrieval, suitable for production-scale applications.
- **Extensibility**: The modular design allows for easy addition of new features (e.g., more social auth providers, event creation).

---

## Conclusion

PlanitApp exemplifies a modern Django application, combining robust authentication, third-party API integration, and best practices in security and user experience. The codebase is clean, modular, and ready for extension, making it an excellent showcase for Django expertise and full-stack development skills.