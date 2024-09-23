import random
import string

def generate_invoice_number():
    prefix = "INV"  
    random_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6)) 
    return f"{prefix}-{random_string}"