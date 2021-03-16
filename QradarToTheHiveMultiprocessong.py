#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
import json
import requests
import warnings
import flask
import time
import uuid 
import sys
import time
import re
import xlrd
import xlwt
import xlutils
import timeit
import os

from  multiprocessing import Pool, Process ,current_process
from xlrd import open_workbook
from xlutils.copy import copy
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CustomFieldHelper, CaseTask, CaseObservable

#except requests.exceptions.RequestException as e:
           # sys.exit("Error: {}".format(e))

#except requests.exceptions.RequestException:
          # sys.exit(1)

api = TheHiveApi('http://10.241.93.116:9000','iU+saEmOI4vo1KFsyzljo/FwAt+tllme')
warnings.filterwarnings('ignore')


   
def DomainName(ClientIP,headers,did):
    DomainURL= str(ClientIP+'api/config/domain_management/domains?fields=id%2Cname').strip()
    response_4 = requests.get(DomainURL,headers=headers,verify=False)
    
    if (response_4.status_code)==200:
        domdata=response_4.json()
        
        for l in domdata:
          if int(l['id'])==int(did):
           return(l['name'])
       
    else:
       return(ClientName) 
    
        
             

def OffenseType(ClientIP,headers,offense_type):
    OffenseTypeURL=str(ClientIP+'api/siem/offense_types').strip()
    response_5 = requests.get(OffenseTypeURL,headers=headers,verify=False)


    #print(response_5.status_code) 
    if (response_5.status_code)==200:
        #print("hello")
        ftypedata=response_5.json()
        #print(ftypedata)
        for m in ftypedata:
          #print(int(m['id']),int(offense_type))
          if int(m['id'])==int(offense_type)  :
           return(m['name'])
       
           
    else: return('unknown')
           

def OffensesRequest(ClientName,ClientIP,ClientApi,df,j):

          headers = {'accept': 'application/json', 'SEC':str(ClientApi), 'Version': '12.1'}
          #print(headers)
          url=str(ClientIP+'api/siem/offenses?fields=id%2Cstatus%2Cdescription%2Coffense_type%2Coffense_source%2Cmagnitude%2Csource_network%2Cdestination_networks%2Cassigned_to%2Cstart_time%2Cevent_count%2Cdomain_id%2Cfollow_up%2Ccategories%2Cseverity')
          #print(url) 


          session = requests.session()
          session.max_redirects=1000
          #session.allow_redirects=False
          response_1 = session.get(url,headers=headers,verify=False)

                

          #session.resolve_redirects(response_1,response_1.request)
          print(ClientName, "RESPONSE 1 CODE: ",response_1.status_code)

          
          if (response_1.status_code) == 200:
                
                    data = response_1.json()
                    last_id = str(data[0]['id'])
                    last_line=int(last_id)-1

                    if int(df)==0:
                                last_line = int(last_id)-1
                                sheet1.write(int(j),4,last_id)
                                wb.save('/home/qradar/CustomerList.xls')
                                print("File was empty. To avoid errors, the file has been updated with the ID of the penultimate QRadar offense: "+ str(last_line))
                    else:
                                last_line = int(df)-1
                           
                    if int(last_line) < int(last_id)-1:
                                first_new_offense = int(last_line)
                                diff = int(last_id) - first_new_offense
                        
                                for k in range(0,diff):
                                            i=diff-k
                                            if str(data[i]['domain_id'])=='0':
                                               customer = ClientName
                                            else:
                                               customer = DomainName(ClientIP,headers,str(data[i]['domain_id']))
                                            if customer =='staging' or customer =='Staging':
                                               continue
                                            offenseDescription = str(data[i]['description'])
                                            offenseid = (str(data[i]['id']))
                                            offensetype=OffenseType(ClientIP,headers,str(data[i]['offense_type']))

                                            status=str(data[i]['status'])
                                            if status =='CLOSED':
                                               continue                                 
                                           
                                            offenseMagnitude = (str(data[i]['magnitude']))
                                            categories=str(data[i]['categories'])
                                            followUp =str(data[i]['follow_up'])
                                            offenseEventCount = (str(data[i]['event_count']))
                                            offenseSource = str(data[i]['offense_source'])
                                            offenseSourceNetwork = str(data[i]['source_network'])
                                            offenseDestinationNetworks = str(data[i]['destination_networks'])
                                            assignedTo = str(data[i]['assigned_to'])
                                            starttime=(str(data[i]['start_time'])) 
                                            domainid =(str(data[i]['domain_id']))
                                            severity=(str(data[i]['severity']))
                                            LinkToQradar=str(ClientIP+'/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId='+str(data[i]['id']))
                                           
                                         
                                            tasks = [CaseTask(title='InBox', description= str("offense Type: "+offensetype +', '+"Description: "+ offenseDescription),
                                              flag=bool(followUp),
                                              group=customer,
                                              id=offenseid,
                                              startDate= None )]


                                       
                                            
                                            
                                            customFields = CustomFieldHelper()\
                                                    .add_string('offenseid', (offenseid))\
                                                    .add_string('offensetype',(offensetype))\
                                                    .add_string('status',(status))\
                                                    .add_integer('offensemagnitude',int(offenseMagnitude))\
                                                    .add_string('categories',categories)\
                                                    .add_string('followup',followUp)\
                                                    .add_integer('offenseeventcount', int(offenseEventCount))\
                                                    .add_string('offensesource', offenseSource)\
                                                    .add_string('offensesourcenetwork', offenseSourceNetwork)\
                                                    .add_string('offensedestinationnetworks', offenseDestinationNetworks)\
                                                    .add_string('reasonForClosing', "null")\
                                                    .add_string('assignedto',assignedTo)\
                                                    .add_integer('domainid',int(domainid))\
                                                    .add_date('starttime',int(starttime))\
                                                    .add_string('linktoqradar',LinkToQradar)\
                                                    .add_string('customer',customer)\
                                                    .build()

                                            if int(offenseMagnitude) < 5:
                                                    tlp = '1'
                                            elif int(offenseMagnitude)>4 and int(offenseMagnitude)<8:
                                                    tlp = '2'
                                            elif int(offenseMagnitude)>7:
                                                    tlp= '3'
                                            else:
                                                    tlp='2'

                                            if int(offenseMagnitude) < 3:
                                                    sev = '1'
                                            elif int(offenseMagnitude)>2 and int(offenseMagnitude)<5:
                                                    sev = '2'
                                            elif int(offenseMagnitude)>4 and int(offenseMagnitude)<8:
                                                    sev = '3'
                                            elif int(offenseMagnitude)>7:
                                                    sev = '4'
                                            else:
                                                    sev = '2'
                                          

                                            case = Case(title=offenseDescription, id=offenseid,
                                                    tlp=int(tlp),
                                                    severity = int(sev),
                                                    flag=bool(followUp),
                                                    metrics=["offenseeventcount",int(offenseEventCount)],
                                                    tags=[customer, offensetype,str(offenseMagnitude)],
                                                    description=LinkToQradar,
                                                    tasks=tasks,
                                                               
                                                    customFields=customFields)
                                                
                                            data1 = case.jsonify()
                                          
                                            id = None
                                            response_2 = api.create_case(case)
                                            #print(response_2.json())
                                            if response_2.status_code == 201:
                                                    id = response_2.json()['id']
                                            else:
                                                    print('ko: {}/{}'.format(response_2.status_code, response_2.text))
                                                    sys.exit(0)
                                            
                                            #Link =str(ClientIP+'/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId='+str(data[i]['id']))
                                            #Observables can be use with Cortex analyzers
                                            #link_to_qradar = CaseObservable(dataType='url',
                                                     #data=[str(Link)],
                                                     #tlp=int(tlp),
                                                     #severity=int(sev),
                                                     #ioc=True,
                                                     #tags=[customer, offensetype,'Mag:'+str(offenseMagnitude)],
                                                     #message="Link to Qradar")
                                            
                                            #response_3 = api.create_case_observable(id,link_to_qradar)

                                            
                                            #if response_3.status_code == 201:
                                                 
                                                     #id = response_3.json()[0]['id']
                                                
                                            #else:
                                                    #print('ko: {}/{}'.format(response_3.status_code, response_3.text))
                                                    #sys.exit(0)
                                
                    else:
                        diff = int(last_id) - int(last_line)
                        print(str(diff) + " new offenses.")
                        sheet1.write(j,5,diff)
                        wb.save('/home/qradar/CustomerList.xls')
                        return('True')
          else:
                    print("Can't get offenses, check the configuration.")    
                    return('False')
             
         


def client_process(j):  
 
            process_id = current_process().name
            print(f"Process ID: {process_id}")
            starttime1=timeit.default_timer()
            ClientName=sheet.cell_value(j,0)
            ClientIP =sheet.cell_value(j, 1).strip()
            ClientApi= sheet.cell_value(j,2).strip()
            df =sheet.cell_value(j,4)
            
            warnings.filterwarnings('ignore')
            
            print(ClientName,"    ",ClientIP,"  ",ClientApi)
            success = OffensesRequest(ClientName,ClientIP,ClientApi,df,j) 
            if success=='True':
                  sheet1.write(j,3,'Success')
                  sheet1.write(j,6,timeit.default_timer() - starttime1)
                  wb.save('/home/qradar/CustomerList.xls')
            elif success=='False':
                  sheet1.write(j,3,'Fail')
                  sheet1.write(j,6,timeit.default_timer() - starttime1)
                  wb.save('/home/qradar/CustomerList.xls')
                  #continue

            
if __name__ == '__main__':       
           loc="/home/qradar/CustomerList.xls"
           rb = xlrd.open_workbook(loc)
           sheet = rb.sheet_by_index(0)
           wb=copy(rb)
           sheet1 = wb.get_sheet(0)
           starttime=timeit.default_timer()
            
           processes = []
           r = range(1,sheet.nrows+1)
           numbers=[*r]
           for j in numbers:
                    process = Process(target=client_process,args = (j,))
                    processes.append(process)
                    process.start()
           for process in processes:
                    process.join()
           print("The time difference is :", timeit.default_timer() - starttime)       
           sheet1.write(0,6,timeit.default_timer() - starttime)
           wb.save('/home/qradar/CustomerList.xls')
    


