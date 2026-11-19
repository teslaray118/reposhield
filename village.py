from pipes import supply_water

print("--- Starting Water Distribution ---")
for house in range(1, 4):
    supply_water(house, 50)
print("--- Done ---")
