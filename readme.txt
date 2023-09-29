This script performs the following actions on an ADuser object.

Disables the user's account
Clears the Manager and direct report fields
Removes all memberships
Moves AD account to the Departed users OU
Moves the Home and Profile Folders to the Archive server
Sends an email detailing the name of the departed user and the memberships they were given.


When running the script please make sure to answer the following questions
1. Enter your email address
2. Enter your Domain Admin Credientials **IMPORTANT**
3. Enter the username of the departed user.
NOTE: If the user has already been departed or the username doesn't exist, you will recieve a message in the 
terminal window. 

4. Enter a time you would like the script run. IE: 6:00pm or 6pm **IMPORTANT**
5. Verify the user to be disabled by entering "Y" and hit Enter

At this point you can minimize the script. DO NOT CLOSE.
Once the target time is hit the rest of the script will run. You will get a confirmation email when completed. 
