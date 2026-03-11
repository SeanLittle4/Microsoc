@echo off
start powershell -NoExit -Command "cd 'C:\Users\seanl\Documents\microsoc_app\microsoc\microsoc\backend'; venv\Scripts\activate; python app.py"
start powershell -NoExit -Command "cd 'C:\Users\seanl\Documents\microsoc_app\microsoc\microsoc\frontend'; npm run dev"