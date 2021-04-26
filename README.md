# Nyan-Hunter
A PowerShell analyzer for AzureAD sign-in logs. It detects password-spraying/brute-forcing attacks and any successful hit.  

*I am no Powershell nor GitHub expert. Please help me improve it.*

Please change the "[CHANGE_ME]" value in the script to yours.

### Prerequisites:
MS Graph API App on AzureAD, including tenant ID, client ID, API key, etc.  
Please refer to: https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0&tabs=http.

### Usage:
```
./Nyan-Hunter.ps1 -timeback <x> [-skip] [-limit <x>] [-file]
```

The script accepts up to 4 parameters  
-timeback: x hour(s) worth of logs from the running time or since the last run time (which saved in ./NyanData/lastrun.txt). Whichever closer.  
-skip: ignore the last run time, get the exact x hour(s) of the -timeback  
-limit: amount of logs, 100,000 by default  
-file: analyze the offline log files  

### Sample output:

![image](https://user-images.githubusercontent.com/66635269/114281962-523f5000-9a0f-11eb-8bdf-fb4533757d2f.png)
![image](https://user-images.githubusercontent.com/66635269/114281990-7438d280-9a0f-11eb-9d74-46b0f04fe619.png)
![image](https://user-images.githubusercontent.com/66635269/114282006-887ccf80-9a0f-11eb-88d4-65751bfbfdde.png)
