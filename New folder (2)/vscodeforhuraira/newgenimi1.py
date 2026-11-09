first_name = input("Enter your first name : ")
last_name = input("Enter your last name: ")
birth_day = input("Enter your birthday: ")

first_part = first_name[0].lower()

second_part = last_name[0:4].lower()

user_name = f"{first_part}{second_part}{birth_day}@company.com"

print(f"Your corparate username is : {user_name}")