from base_calculator import *
from temporal_calculator import *
from environmental_calculator import *
import json


cvss_keys = {
    "AV":   "Access Vector",
    "AC":   "Access Complexity",
    "Au":   "Authentication",
    "C":    "Confidentiality Impact",
    "I":    "Integrity Impact",
    "A":    "Availability Impact",

    "E":    "Exploitability",
    "RL":   "Remediation Level",
    "RC":   "Report Confidence",

    "CDP":  "Collateral Damage Potential",
    "TD":   "Target Distribution",
    "CR":   "Confidentiality Requirement",
    "IR":   "Integrity Requirement",
    "AR":   "Availability Requirement"
}
cvss_values = {
    "AV":   {
        "L":    "Local",
        "A":    "Adjacent Network",
        "N":    "Network"},
    "AC":   {
        "H":    "High",
        "M":    "Medium",
        "L":    "Low"},
    "Au":   {
        "M":    "Multiple",
        "S":    "Single",
        "N":    "None"},
    "C":    {
        "N":    "None",
        "P":    "Partial",
        "C":    "Complete"},
    "I":    {
        "N":    "None",
        "P":    "Partial",
        "C":    "Complete"},
    "A":    {
        "N":    "None",
        "P":    "Partial",
        "C":    "Complete"},

    "E":    {
        "U":    "Unproven",
        "POC":  "Proof of Concept",
        "F":    "Functional",
        "H":    "High",
        "ND":   "Not Defined"},
    "RL":   {
        "OF":   "Official Fix",
        "TF":   "Temporary Fix",
        "W":    "Workaround",
        "U":    "Unavailable",
        "ND":   "Not Defined"},
    "RC":   {
        "UC":   "Unconfirmed",
        "UR":   "Uncorroborated",
        "C":    "Confirmed",
        "ND":   "Not Defined"},

    "CDP":  {
        "N":    "None",
        "L":    "Low",
        "LM":   "Low-Medium",
        "MH":   "Medium-High",
        "H":    "High",
        "ND":   "Not Defined"},
    "TD":   {
        "N":    "None",
        "L":    "Low",
        "M":    "Medium",
        "H":    "High",
        "ND":   "Not Defined"},
    "CR":   {
        "L":    "Low",
        "M":    "Medium",
        "H":    "High",
        "ND":   "Not Defined"},
    "IR":   {
        "L":    "Low",
        "M":    "Medium",
        "H":    "High",
        "ND":   "Not Defined"},
    "AR":   {
        "L":    "Low",
        "M":    "Medium",
        "H":    "High",
        "ND":   "Not Defined"}
}

def severity(score):
    if score == 0.0:
        return "None"
    elif score >= 0.1 and score < 4.0:
        return "Low"
    elif score >= 4.0 and score < 7.0:
        return "Medium"
    elif score >= 7.0 and score < 9.0:
        return "High"
    elif score > 9.0 and score <= 10.0:
        return "Critical"
    else:
        raise "CVSS score is out of bounds"


def get_scores(path, show_calculations=False):

    file = open(path)

    data = json.load(file)

    access_vector = assign_access_vector(data["Base"]["AV"])
    access_complexity = assign_access_complexity(data["Base"]["AC"])
    authentication = assign_authentication(data["Base"]["Au"])
    confidentiality_impact = assign_confidentiality_impact(data["Base"]["C"])
    integrity_impact = assign_integrity_impact(data["Base"]["I"])
    availability_impact = assign_availability_impact(data["Base"]["A"])

    impact = calculate_impact(confidentiality_impact, integrity_impact, availability_impact)
    exploitability = calculate_exploitability(access_vector, access_complexity, authentication)
    f_impact = calculate_f_impact(impact)

    base_score = calculate_base(impact, exploitability, f_impact)


    temporal_exploitability = assign_temporal_exploitability(data["Temporal"]["E"])
    remediation_level = assign_remediation_level(data["Temporal"]["RL"])
    report_confidence = assign_report_confidence(data["Temporal"]["RC"])

    temporal_score = calculate_temporal(base_score, temporal_exploitability, remediation_level, report_confidence)


    collateral_damage_potential = assign_collateral_damage_potential(data["Environmental"]["CDP"])
    target_distribution = assign_target_distribution(data["Environmental"]["TD"])
    confidentiality_requirement = assign_confidentiality_requirement(data["Environmental"]["CR"])
    integrity_requirement = assign_integrity_requirement(data["Environmental"]["IR"])
    availability_requirement = assign_availability_requirement(data["Environmental"]["AR"])

    adjusted_impact = calculate_adjusted_impact(confidentiality_impact, integrity_impact, availability_impact, confidentiality_requirement, integrity_requirement, availability_requirement)
    adjusted_base_score = calculate_base(adjusted_impact, exploitability, f_impact)
    adjusted_temporal = calculate_adjusted_temporal(adjusted_base_score, temporal_exploitability, remediation_level, report_confidence)

    environmental_score = calculate_environmental(adjusted_temporal, collateral_damage_potential, target_distribution)

    if show_calculations:
        access_vector_in_words = cvss_values["AV"][data["Base"]["AV"]]
        access_complexity_in_words = cvss_values["AC"][data["Base"]["AC"]]
        authentication_in_words = cvss_values["Au"][data["Base"]["Au"]]
        confidentiality_impact_in_words = cvss_values["C"][data["Base"]["C"]]
        integrity_impact_in_words = cvss_values["I"][data["Base"]["I"]]
        availability_impact_in_words = cvss_values["A"][data["Base"]["A"]]
        exploitability_in_words = cvss_values["E"][data["Temporal"]["E"]]
        remediation_level_in_words = cvss_values["RL"][data["Temporal"]["RL"]]
        report_confidence_in_words = cvss_values["RC"][data["Temporal"]["RC"]]
        collateral_damage_potential_in_words = cvss_values["CDP"][data["Environmental"]["CDP"]]
        target_distribution_in_words = cvss_values["TD"][data["Environmental"]["TD"]]
        confidentiality_requirement_in_words = cvss_values["CR"][data["Environmental"]["CR"]]
        integrity_requirement_in_words = cvss_values["IR"][data["Environmental"]["IR"]]
        availability_requirement_in_words = cvss_values["AR"][data["Environmental"]["AR"]]

        print("-----------------------------------------------------------")
        print("BASE METRIC EVALUATION SCORE")
        print("-----------------------------------------------------------")
        print("Access Vector [%s] (%s)" % (access_vector_in_words, access_vector))
        print("Access Complexity [%s] (%s)" % (access_complexity_in_words, access_complexity))
        print("Authentication [%s] (%s)" % (authentication_in_words, authentication))
        print("Confidentiality Impact [%s] (%s)" % (confidentiality_impact_in_words, confidentiality_impact))
        print("Integrity Impact [%s] (%s)" % (integrity_impact_in_words, integrity_impact))
        print("Availability Impact [%s] (%s)" % (availability_impact_in_words, availability_impact))
        print("-----------------------------------------------------------")
        print("FORMULA BASE SCORE")
        print("-----------------------------------------------------------")
        print("Impact = 10.41*(1-(1-%s)*(1-%s)*(1-%s)) == %s" % (confidentiality_impact, integrity_impact, availability_impact, impact))
        print("Exploitability = 20* %s*%s*%s == %s" % (access_vector, access_complexity, authentication, exploitability))
        print("f(Impact) = %s" % f_impact)
        print("BaseScore = round(((0.6*%s)+(0.4*%s)-1.5)*%s)" % (impact, exploitability, f_impact))
        print("== (%s)" % base_score)
        print("-----------------------------------------------------------")
        print("-----------------------------------------------------------")
        print("TEMPORAL METRIC EVALUATION SCORE")
        print("-----------------------------------------------------------")
        print("Exploitability [%s] (%s)" % (exploitability_in_words, temporal_exploitability))
        print("Remediation Level [%s] (%s)" % (remediation_level_in_words, remediation_level))
        print("Report Confidence [%s] (%s)" % (report_confidence_in_words, report_confidence))
        print("-----------------------------------------------------------")
        print("FORMULA TEMPORAL SCORE")
        print("-----------------------------------------------------------")
        print("round(%s*%s*%s*%s) == %s" % (base_score, temporal_exploitability, remediation_level, report_confidence, temporal_score))
        print("-----------------------------------------------------------")
        print("-----------------------------------------------------------")
        print("ENVIRONMENTAL METRIC EVALUATION SCORE")
        print("-----------------------------------------------------------")
        print("Collateral Damage Potential [%s] (%s)" % (collateral_damage_potential_in_words, collateral_damage_potential))
        print("Target Distribution [%s] (%s)" % (target_distribution_in_words, target_distribution))
        print("Confidentiality Req. [%s] (%s)" % (confidentiality_requirement_in_words, confidentiality_requirement))
        print("Integrity Req. [%s] (%s)" % (integrity_requirement_in_words, integrity_requirement))
        print("Availability Req. [%s] (%s)" % (availability_requirement_in_words, availability_requirement))
        print("-----------------------------------------------------------")
        print("FORMULA ENVIRONMENTAL SCORE")
        print("-----------------------------------------------------------")
        print("AdjustedImpact = min(10,10.41*(1-(1-%s*%s)*(1-%s*%s)*(1-%s*%s))) == %s" % (confidentiality_impact, confidentiality_requirement, integrity_impact, integrity_requirement, availability_impact, availability_requirement, adjusted_impact))
        print("AdjustedBase = round(((0.6*%s)+(0.4*%s)-1.5)*%s) == %s" % (adjusted_impact, exploitability, f_impact, adjusted_base_score))
        print("AdjustedTemporal = round(%s*%s*%s*%s) == %s" % (adjusted_base_score, temporal_exploitability, remediation_level, report_confidence, adjusted_temporal))
        print("EnvScore = round((%s+(10-%s)*%s)*%s)" % (adjusted_temporal, adjusted_temporal, collateral_damage_potential, target_distribution))
        print("== (%s)" % environmental_score)
        print("-----------------------------------------------------------")

    file.close()
    return base_score, temporal_score, environmental_score
