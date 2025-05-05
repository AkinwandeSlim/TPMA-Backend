class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost:5432/tpma'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'x7k9p2m4q8r5t1n3'  # Replace with a secure key
    UPLOAD_FOLDER = 'uploads'  # Directory for uploaded files