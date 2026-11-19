def pump_water(household_id, volume, pressure=0.0):
    print(f"Pumping {volume}L of water to household #{household_id}")
    print(f"Water pressure: {pressure} PSI")


def deliver_water(household_id, volume_liters, pressure_psi=0.0):
    """Maintain backward compatibility with school.py."""
    return pump_water(
        household_id,
        volume_liters,
        pressure=pressure_psi
    )


def supply_water(household_id, liters):
    return pump_water(household_id, liters, pressure=0.0)