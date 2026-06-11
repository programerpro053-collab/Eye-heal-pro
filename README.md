Project Overview
EyeHeal Pro is an advanced AI and computer vision system for monitoring eye health and analyzing eye movements in real time. The system is designed to provide accurate, real-time analysis and periodic data storage, helping users track their eye health and analyze patterns over time.

Engineering Highlights
Real-time Computer Vision: Utilizes the MediaPipe and OpenCV libraries for high-resolution video streaming, implementing mapping algorithms to identify sensitive eye points.

Multi-threaded Architecture: Employs threading techniques for background data processing, ensuring smooth video streaming without impacting user interface responsiveness.

Modular Data Handling: An integrated data management system using SQLite ensures record sustainability and the ability to retrieve and analyze historical user patterns.

Interactive Data Visualization: An interactive graphical interface built with Pygame displays real-time charts and supports exporting professional PDF reports via ReportLab. Scalable Codebase: A software architecture based on object-oriented programming (OOP) to ensure scalability and the addition of new features in the future.

Technologies Used (Tech Stack)
Core: Python

Vision: OpenCV, MediaPipe

Interface & Charts: Pygame

Database: SQLite

Reporting: ReportLab, PDFPlumber

Math & Data: NumPy

Installation & Setup
Configure the environment:

Bash

pip install opencv-python mediapipe numpy pygame reportlab pdfplumber
Run the main program:

Bash

python "EyeHeal Pro.py"
