from base_calculator import round_to_1_decimal

def calculate_temporal(base_score, temporal_exploitability, remediation_level, report_confidence):
    return round_to_1_decimal(base_score*temporal_exploitability*remediation_level*report_confidence)

def assign_temporal_exploitability(abbreviation):
    match abbreviation:
        case "U":
            return 0.85
        case "POC":
            return 0.9
        case "F":
            return 0.95
        case "H":
            return 1.0
        case "ND":
            return 1.0

def assign_remediation_level(abbreviation):
    match abbreviation:
        case "OF":
            return 0.87
        case "TF":
            return 0.9
        case "W":
            return 0.95
        case "U":
            return 1.0
        case "ND":
            return 1.0

def assign_report_confidence(abbreviation):
    match abbreviation:
        case "UC":
            return 0.9
        case "UR":
            return 0.95
        case "C":
            return 1.0
        case "ND":
            return 1.0
