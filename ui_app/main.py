# ui-app/main.py

import os
from dotenv import load_dotenv
from app import App

def main():
    """
    Main entry point for the application.
    Loads environment variables and starts the UI.
    """
    dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(dotenv_path=dotenv_path)
    
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()