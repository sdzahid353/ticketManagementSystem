# Ticket Management System

## Installing virtualenv

### On macOS and Linux:

    python3 -m pip install --user virtualenv (pip install virtualenv)

### On Windows:

    py -m pip install --user virtualenv (pip install virtualenv)


## Creating a virtual environment¶

### On macOS and Linux:

    python3 -m venv env (virtualenv venv)

### On Windows:

    py -m venv env (virtualenv venv)


## Activating a virtual environment¶

### On macOS and Linux:

    source venv/bin/activate

### On Windows:

    .\venv\Scripts\activate.bat


## Leaving the virtual environment

    deactivate


## Using requirements files

    pip install -r requirements.txt


## Freezing dependencies

    pip freeze > requirements.txt

    pip freeze


## Installing Requirements

    pip install django
    pip install djangorestframework
