# ERP System for the Faculty of Engineering, University of Ruhuna

## Overview

This project is an ERP system designed for the Faculty of Engineering at the University of Ruhuna. The system comprises five portals, with the Admin Portal being our primary focus. This portal handles role-based authentication, user management, and SMS and email integrations.

## Key Features

- **Authentication**
  - JWT and refresh tokens for secure access
  - Two-factor authentication (2FA)
  - Email confirmation
  - Device login tracking with email notifications for new devices

- **User Management**
  - Comprehensive user management system
  - Role assignments and permissions control

- **Communication Integration**
  - SMS and email services

## Technologies Used

- **Frontend:** Blazor
- **Backend:** ASP.NET Core APIs with a microservices architecture
- **API Gateway:** Ocelot API Gateway
- **Message Broker:** RabbitMQ
- **Database:** PostgreSQL
- **Framework:** .NET 8

## Repository Structure

The backend and frontend are maintained in separate repositories to ensure modularity and ease of development.

### Frontend Repository

- **Location:** [Frontend Repository URL](https://github.com/Shenith404/ERP.Admin.Portal.Microservices)
- **Technologies:** Blazor, HTML, CSS, JavaScript

### Backend Repository

- **Location:** [Backend Repository URL](#)
- **Technologies:** ASP.NET Core, Ocelot, RabbitMQ, PostgreSQL

## Getting Started

### Prerequisites

- .NET 8 SDK
- PostgreSQL
- RabbitMQ
- Node.js (for frontend dependencies)


