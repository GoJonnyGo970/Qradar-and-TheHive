# Qradar-and-TheHive
Scripts for TheHive and IBm Qradar
This is very customized for CarbonHelix use scenerio, but it addresses many of the possible needs of future users who are trying to adapt Pierre Bartletts QradarToHive.py script

The script loops through  a list of Clients (Ip, api key) stored in an .xls worksheet and pulls Qradar offense data using the Qradar Rest Api method for offense, offense type, and domain data. 
The data is populated into TheHive4py by use of both existing and custom fields. Of particular interest if the creation of a URL Link back to Qradar that is placed in the Case Description field.
It is important to note that CarbonHelix is NOT using Alerts but going straight to Case with the data. 
The initial intended use is to create a list of all incoming Offenses for Analysts to "take". 
Phase one of TheHive is a management tool for tracking Offenses, monitoring time on task,response time, filtering and sorting, and assignees. 
Phase two will move towards updating status in qradar, updating severity, etc in qradar from theHive so that analysts can complete and document their work all in TheHive.
Phase three will be to integrate Cortex into the Playbook so that repetitive tasks can become more efficiently addressed.

The lateste version uses a csv. has to have at least one line in it to start and the fields need the last_offense and NewOpen populated with "#0" and a datetime in the last_process date of the form mm/dd/yyyy hh:mm:ss:ms. 

Update 04-08-2021: I have made several iterative changes and believe the lastest version to be the most accurate and stable, yet. Going to production with this one.
