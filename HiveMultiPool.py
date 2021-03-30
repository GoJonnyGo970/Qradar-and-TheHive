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
import xlutils
import timeit
import os
import pandas as pd
from  multiprocessing import Pool, Process ,current_process,get_context

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
           

def OffensesRequest(ClientName,ClientIP,ClientApi,lof,j):
          #df=pd.read_csv('Client.csv',usecols=col,dtype={'Client_Name':str,'Link_for_Console':str,'Token':str,'Status':str,'Last_offense':str,'NewOpen':str,'Process_time':str,'error_msg':str,'Last_Process_Date':str},index_col=False)
          headers = {'accept': 'application/json', 'SEC':str(ClientApi), 'Version': '12.1','range':'items=0-49'}
          #print(headers)
          url=str(str(ClientIP)+'api/siem/offenses?fields=id%2Cstatus%2Cdescription%2Coffense_type%2Coffense_source%2Cmagnitude%2Csource_network%2Cdestination_networks%2Cassigned_to%2Cstart_time%2Cevent_count%2Cdomain_id%2Cfollow_up%2Ccategories%2Cseverity')
          #print(url) 


          session = requests.session()
          session.max_redirects=1000
          #session.allow_redirects=False
          response_1 = session.get(url,headers=headers,verify=False)
                
          #response_1 = session.get(url,headers=headers,verify=False)
          #session.resolve_redirects(response_1,response_1.request)
          print(ClientName, "RESPONSE 1 CODE: ",response_1.status_code)

          
          if (response_1.status_code) == 200:
                
                    data = response_1.json()
                    #print(data)
                    last_id = str(data[0]['id'])
                    print(ClientName,last_id,lof)
                    rangecheck = int(last_id)-int(lof)

                    if rangecheck>=49:
                        headers = {'accept': 'application/json', 'SEC':str(ClientApi), 'Version': '12.1','range':str('items=0-'+str(rangecheck))}
                        response_1 = session.get(url,headers=headers,verify=False)
                        data = response_1.json()
                        last_id = str(data[0]['id'])
                   

    

                    last_line = int(last_id)-1

                    if lof=='0'or int(lof)==0 or lof=='#0':
                                last_line = int(last_id)-5
                                print(ClientName+", "+"File was empty. To avoid errors, the file has been updated with the ID of the penultimate QRadar offense: "+ str(last_id))
                    elif int(last_id)!=int(lof):
                                last_line = int(lof)
                    elif int(last_id)==int(lof):
                                 print("no new offense for: ",ClientName)
                                 return("NoNew",response_1.status_code)
                           
                    first_new_offense = int(last_line)
                    diff = int(last_id) - first_new_offense
                    col=[0,1,2,3,4,5,6,7,8]                
                    df=pd.read_csv('Client.csv',usecols=col)
                    df.iat[int(j),4]=str('#'+str(last_id))
                    df.iat[int(j),5]=str('#'+str(diff))
                    df.to_csv('Client.csv',index=False)
                    
                    #print("This is where lastline is compared to last_id",last_line,"  ",last_id)
                    if int(last_line) < int(last_id):
                                print("Client : ", ClientName,"lastID: ",last_id,"last_line: ",last_line,"diff :",diff,"ClientName: ",ClientName)
                                col=[0,1,2,3,4,5,6,7,8]                
                                df=pd.read_csv('Client.csv',usecols=col)

                                df.iat[int(j),4]=str('#'+str(last_id))
                                df.iat[int(j),5]=str('#'+str(diff))
                                df.to_csv('Client.csv',index=False)





                                for k in range(0,diff):
                                            i=diff-k
                                            print(ClientName,": i=",i)
                                            if str(data[i]['domain_id'])=='0':
                                               customer = ClientName
                                            else:
                                               customer = DomainName(ClientIP,headers,str(data[i]['domain_id']))
                                            if customer =='staging' or customer =='Staging':
                                               continue
                                            offenseDescription = str(data[i]['description'])
                                            offenseid = (str(data[i]['id']))
                                            #("offenseID: ",offenseid,"customer: ",customer)
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
                                           
                                         
                                            tasks = [CaseTask(title='InBox', description= str("offense Type: "+str(offensetype) +', '+"Description: "+ str(offenseDescription)),
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
                                            #print(data1)
                                            id = None
                                            response_2 = api.create_case(case)
                                            print(ClientName+": r2scode: "+str(response_2.status_code)+" iteration: "+str(i))
                                            if response_2.status_code == 201:
                                                    id = response_2.json()['id']
                                            else:
                                                    print('ko: {}/{}'.format(response_2.status_code, response_2.text))
                                                    col=[0,1,2,3,4,5,6,7,8]                
                                                    df=pd.read_csv('Client.csv',usecols=col)
                                                    df.iat[j,7] =response_2.status_code
                                                    df.to_csv('Client.csv',index=False)
                                                    continue
                                                    #sys.exit(0)
                                               
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
   
                                               
                    return('True',response_1.status_code)
          else:
                    print("Can't get offenses, check the configuration.")   
                    return('False',response_1.status_code)
      
         

def client_process(j):
   
      col=[0,1,2,3,4,5,6,7,8] 
      df=pd.read_csv('Client.csv',usecols=col,index_col=False)
      process_id = current_process().name
      print(f"pocess ID: {process_id}")
      ClientName=df.values[j][0]
      ClientIP=df.values[j][1]
      ClientApi=df.values[j][2]
      ClientIP=ClientIP.strip()
      ClientName=ClientName.strip()
      ClientApi=ClientApi.strip()
      lofs= df['Last_offense'].str.split('#').str[1]

      lof=lofs.values[j]
      print(lof)
      starttime1=time.process_time()
      df.iat[j,8]=str(pd.to_datetime(time.time(), unit='s'))
      df.to_csv('Client.csv',index=False)
    
        			
      warnings.filterwarnings('ignore')
				
      print("sent to Request:",ClientName,ClientIP,ClientApi,lof,j)
      
      try:
            success,response = OffensesRequest(ClientName,ClientIP,ClientApi,lof,j)

      except Exception as e:
            print(str(pd.to_datetime(time.time(), unit='s'))+"  "+ClientName+" Error: "+ str(e))
      finally:
           pass
      success,response = OffensesRequest(ClientName,ClientIP,ClientApi,lof,j)
      print(success,response) 
      if success=='True':
         stoptime1=time.process_time()
         client_time =stoptime1-starttime1
         print(ClientName,'Success',client_time)
         col=[0,1,2,3,4,5,6,7,8] 
         df=pd.read_csv('Client.csv',usecols=col,index_col=False)
         df.iat[j,3]='Success'
         df.iat[j,6] = str(client_time)
         df.to_csv('Client.csv',index=False)
      elif success=='False':
         stoptime1=time.process_time()
         client_time =stoptime1-starttime1
         print(ClientName,'Fail',client_time)
         col=[0,1,2,3,4,5,6,7,8] 
         df=pd.read_csv('Client.csv',usecols=col,index_col=False)
         df.iat[j,3]='Fail'
         df.iat[j,7]=response
         df.iat[j,6]=str(client_time)
         df.to_csv('Client.csv',index=False)
      elif  success=='NoNew':
         stoptime1=time.process_time()
         client_time =stoptime1-starttime1
         print(ClientName,'NoNew',client_time)
         col=[0,1,2,3,4,5,6,7,8] 
         df=pd.read_csv('Client.csv',usecols=col,index_col=False)
         df.iat[j,3]='NoNew'
         df.iat[int(j),5]=str('#'+'0')
         df.iat[j,6]=str(client_time)
         df.to_csv('Client.csv',index=False)
      return()

def method_process():

    col=[0,1,2,3,4,5,6,7,8] 
    df=pd.read_csv('Client.csv',usecols=col,index_col=False)
    processes = []
    r = range(0,len(df))
    numbers=[*r]
    for j in numbers:
             
             #result=client_process(j)
             process = Process(target=client_process,args = (j,))
             processes.append(process)
             process.start()
    for process in processes:
             process.join()
             process.close
    return()

def method_pool():	
    col=[0,1,2,3,4,5,6,7,8] 
    df=pd.read_csv('Client.csv',usecols=col,index_col=False)
    r = range(0,len(df))
    numbers=[*r]
    with get_context("spawn").Pool() as p:
      #p=Pool()
       result=p.map(client_process,numbers)
       p.close()
       p.join()
    return()
   

def method_no_multi():
    col=[0,1,2,3,4,5,6,7,8] 
    df=pd.read_csv('Client.csv',usecols=col,index_col=False)                                                                                                         
    r = range(0,len(df))
    numbers=[*r]
    for j in numbers:
             
             result=client_process(j)
    return()  
			   
            
if __name__ == '__main__': 
    #SELECT WHICH PROCESS YOU WANT TO RUN BY REMOVING THE '#' IN FRONT OF IT.mAKE SUR THE OTHER TWO HAVE A '#'.   
    tmain_start=time.perf_counter()
    #logf = open('Hive.log','w')

    #method_no_multi()
    method_pool()
    #method_process()

    tmain_stop=time.perf_counter()
    #logf.close 
    print("The time difference is :", tmain_stop-tmain_start)       
    #df.iat[0,6]=timeit.default_timer() - starttime
    #df.to_csv('Client.csv',index=False)
    
