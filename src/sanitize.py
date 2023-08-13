import re
def hostname(input_str):
    # Substituir espaços em branco por underscores
    sanitized_str = re.sub(r'[^a-zA-Z0-9\-]', '_', input_str)
    
    # Certificar-se de que o nome começa e termina com um caractere alfanumérico
    sanitized_str = re.sub(r'^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$', '', sanitized_str)
    
    # Limitar o comprimento do hostname a 63 caracteres (limite comum)
    sanitized_str = sanitized_str[:63]
    
    # Substituir traços consecutivos por um único traço
    sanitized_str = re.sub(r'\-+', '-', sanitized_str)
    
    return sanitized_str