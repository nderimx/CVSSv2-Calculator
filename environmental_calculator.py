from base_calculator import round_to_1_decimal

def calculate_environmental(adjusted_temporal, collateral_damage_potential, target_distribution):
    return round_to_1_decimal((adjusted_temporal + (10 - adjusted_temporal)*collateral_damage_potential)*target_distribution)

def calculate_adjusted_temporal(adjusted_base_score, exploitability, remediation_level, report_confidence):
    return round_to_1_decimal(adjusted_base_score*exploitability*remediation_level*report_confidence)

def calculate_adjusted_impact(confidentiality_impact, integrity_impact, availability_impact, confidentiality_requirement, integrity_requirement, availability_requirement):
    return min(10, 10.41*(1- (1 - confidentiality_impact*confidentiality_requirement)*(1 - integrity_impact*integrity_requirement)*(1 - availability_impact*availability_requirement)))

def assign_collateral_damage_potential(abbreviation):
    match abbreviation:
        case "N":
            return 0.0
        case "L":
            return 0.1
        case "LM":
            return 0.3
        case "MH":
            return 0.4
        case "H":
            return 0.5
        case "ND":
            return 0.0

def assign_target_distribution(abbreviation):
    match abbreviation:
        case "N":
            return 0.0
        case "L":
            return 0.25
        case "M":
            return 0.75
        case "H":
            return 1.0
        case "ND":
            return 1.0

def assign_confidentiality_requirement(abbreviation):
    match abbreviation:
        case "L":
            return 0.5
        case "M":
            return 1.0
        case "H":
            return 1.51
        case "ND":
            return 1.0
def assign_integrity_requirement(abbreviation):
    match abbreviation:
        case "L":
            return 0.5
        case "M":
            return 1.0
        case "H":
            return 1.51
        case "ND":
            return 1.0
def assign_availability_requirement(abbreviation):
    match abbreviation:
        case "L":
            return 0.5
        case "M":
            return 1.0
        case "H":
            return 1.51
        case "ND":
            return 1.0
