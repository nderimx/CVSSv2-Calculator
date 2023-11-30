def round_to_1_decimal(decimal):
    return round(decimal, 1)

def calculate_base(impact, exploitability, f_impact):
    return round_to_1_decimal(((0.6*impact) + (0.4*exploitability) - 1.5)*f_impact)

def calculate_impact(confidentiality_impact, integrity_impact, availability_impact):
    return 10.41*(1 - (1 - confidentiality_impact)*(1 - integrity_impact)*(1 - availability_impact))

def calculate_exploitability(access_vector, access_complexity, authentication):
    return 20*access_vector*access_complexity*authentication

def calculate_f_impact(impact):
    if impact == 0:
        return 0
    else:
        return 1.176

def assign_access_vector(abbreviation):
    match abbreviation:
        case "L":
            return 0.395
        case "A":
            return 0.646
        case "N":
            return 1.0

def assign_access_complexity(abbreviation):
    match abbreviation:
        case "H":
            return 0.35
        case "M":
            return 0.61
        case "L":
            return 0.71

def assign_authentication(abbreviation):
    match abbreviation:
        case "M":
            return 0.45
        case "S":
            return 0.56
        case "N":
            return 0.704

def assign_confidentiality_impact(abbreviation):
    match abbreviation:
        case "N":
            return 0.0
        case "P":
            return 0.275
        case "C":
            return 0.660

def assign_integrity_impact(abbreviation):
    match abbreviation:
        case "N":
            return 0.0
        case "P":
            return 0.275
        case "C":
            return 0.660

def assign_availability_impact(abbreviation):
    match abbreviation:
        case "N":
            return 0.0
        case "P":
            return 0.275
        case "C":
            return 0.660

