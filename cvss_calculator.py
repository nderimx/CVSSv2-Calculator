from base_calculator import *
from temporal_calculator import *
from environmental_calculator import *
import json

def get_scores(path):

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

    file.close()

    return base_score, temporal_score, environmental_score
