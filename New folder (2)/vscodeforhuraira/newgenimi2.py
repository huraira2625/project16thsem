age = int(input("Enter your age : "))
is_tuesday_input = input("Is it Tuesday? (yes/no): ").lower()

is_tuesday = is_tuesday_input == "yes"

if age < 5:
    price = 0
elif age >= 65:
    price = 8
else:
    if is_tuesday:
        price = 9
    else:
        price = 12
print(f"\nYour movie ticket price is: ${price}")