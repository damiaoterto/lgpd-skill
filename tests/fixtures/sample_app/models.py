# Sample database model representing users and medical files
from datetime import datetime

class User:
    def __init__(self, full_name, email, cpf, phone, password_hash):
        self.full_name = full_name
        self.email = email
        self.cpf = cpf
        self.phone = phone
        self.password_hash = password_hash
        self.deleted_at = None

class PatientRecord:
    def __init__(self, user_id, blood_type, medical_diagnosis):
        self.user_id = user_id
        self.blood_type = blood_type
        self.medical_diagnosis = medical_diagnosis
