## Installation

1. Create a virtual environment by running `py -m venv env`.
2. Activate the virtual environment by running `source env/bin/activate` (on Mac/Linux) or `.\env\Scripts\activate` (on Windows).
3. Install all project dependencies by running `pip install -r requirements.txt`.
4. Generate the database migration files by running `py manage.py makemigrations`.
5. Apply the database migrations by running `py manage.py migrate`.
6. Start the development server by running `py manage.py runserver`.

Note: If you're using Windows PowerShell, you may need to set the execution policy by running `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` before activating the virtual environment.
