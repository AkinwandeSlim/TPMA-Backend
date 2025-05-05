from mockup import save_users, users
save_users(users)
# import json

# # Load the users.json file
# with open("users.json", "r") as f:
#     users = json.load(f)

# # Fix any password fields that are bytes
# for trainee in users.get("teacherTrainee", []):
#     if isinstance(trainee["password"], bytes):
#         trainee["password"] = trainee["password"].decode("utf-8")
#     elif isinstance(trainee["password"], str) and trainee["password"].startswith("b'"):
#         # Remove the b' prefix and trailing ' if present
#         trainee["password"] = trainee["password"][2:-1]

# # Save the updated users.json
# with open("users.json", "w") as f:
#     json.dump(users, f, indent=4)

# print("users.json has been cleaned.")

# # # Migration script (run once)
# # with app.app_context():
# #     with open("users.json", "r") as f:
# #         old_users = json.load(f)
    
# #     for role, user_list in old_users.items():
# #         if role == "lessons":
# #             for lesson in user_list:
# #                 new_lesson = Lesson(
# #                     id=lesson["id"],
# #                     supervisorId=lesson["supervisorId"],
# #                     className=lesson["className"],
# #                     subject=lesson["subject"],
# #                     startTime=lesson["startTime"],
# #                     endTime=lesson["endTime"]
# #                 )
# #                 db.session.add(new_lesson)
# #         else:
# #             for user in user_list:
# #                 new_user = User(
# #                     id=user["id"],
# #                     regNo=user.get("regNo"),
# #                     staffId=user.get("staffId"),
# #                     email=user["email"],
# #                     password=user["password"],
# #                     role=user["role"],
# #                     name=user["name"],
# #                     surname=user["surname"],
# #                     phone=user.get("phone", ""),
# #                     address=user["address"],
# #                     bloodType=user["bloodType"],
# #                     sex=user["sex"],
# #                     birthday=user["birthday"],
# #                     placeOfTP=user.get("placeOfTP"),
# #                     placeOfSupervision=user.get("placeOfSupervision"),
# #                     supervisorId=user.get("supervisorId"),
# #                     progress=user.get("progress"),
# #                     img=user.get("img", "")
# #                 )
# #                 db.session.add(new_user)
# #     db.session.commit()