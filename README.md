# Project Setup for ESTC Back End

## Introduction

This guide will walk you through how to clone the project, set up the environment, install necessary dependencies, configure database, and run the server.

---

## 1. Clone the Project

```bash
git clone https://github.com/vnb-it-organisation/repository-ufs_back_end.git
cd repository-ufs_back_end
```

---

## 2. Set Up a Virtual Environment

1. **Create a virtual environment** to keep dependencies isolated:

   #### For Windows:

   ```bash
   python -m venv venv
   ```

   #### For macOS/Linux:

   ```bash
   python3 -m venv venv
   ```

2. **Activate the virtual environment**:

   #### For Windows:

   ```bash
   venv\Scripts\activate
   ```

   #### For macOS/Linux:

   ```bash
   source venv/bin/activate
   ```

---

## 3. Install Dependencies

1. **Install all required packages** by running this command:

   ```bash
   pip install -r requirements.txt
   ```

---



## 4. Run the Server

1. **Apply migrations** to set up the database schema:

   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

2. **Start the Django development server**:

   ```bash
   python manage.py runserver
   ```

3. **Access the project** by going to `http://127.0.0.1:8000/swagger` in your browser.