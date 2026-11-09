total_bill = float(input("Enter the total amount of the bill: $"))
tip_percentage = int(input("Enter the percentage of tip you want to leave: "))

num_people = int(input("Enter the number of people splitting the bill : "))

tip_amount = total_bill * (tip_percentage / 100)
grand_total = total_bill + tip_amount

amount_per_person = grand_total / num_people

final_amount = round(amount_per_person, 2)

print(f"The grand total including tip is : {grand_total: .2f}")
print(f"Each person needs to pay : {final_amount}")