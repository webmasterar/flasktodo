# My Todo

Example Flask/Python web application, storing data on a
Postgresql database.

Features:

    - User registeration/login
    - Google OAuth2 registration/login
    - Create/edit/delete/strikethrough Todos
    - Postgresql database via SQLAlchemy
    - Tailwind CSS styling
    - Vite CSS compilation


## Installation

After installing the following development environment with Python virtual environments:

    - Python 3.12
    - pip 23.2
    - npm 10.2

Clone the project: `git clone https://github.com/webmasterar/flasktodo.git`

Change into the directory, copy and update the environment file `.env`, then modify its contents
to match your local setup in your preferred editor.

```commandline
cd flasktodo
cp example.env .env
vim .env
```

Install the Python modules:

```commandline
pip install -r requirements.txt
```

Install vite and have it build the CSS:

```commandline
npm install
npm run build
```


## Running the app locally

To run it after installing Python and Flask:

```commandline
flask --app app --debug run 
```
