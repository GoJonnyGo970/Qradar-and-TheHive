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
import re
import xlutils
import timeit
import os
import pandas as pd
import datetime
import pytz.reference 
from  multiprocessing import Pool, Process ,current_process,get_context
from requests.adapters import HTTPAdapter
from requests.exceptions import Timeout
from requests.exceptions import ConnectionError
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CustomFieldHelper, CaseTask, CaseObservable

api = TheHiveApi('URL','YOUR KEY)
warnings.filterwarnings('ignore')


   
def DomainName(ClientIP,ClientApi,did):
    DomainURL= str(ClientIP+'api/config/domain_management/domains?fields=id%2Cname').strip()
    headers = {'accept': 'application/json', 'SEC':str(ClientApi),'range':'all'}

    response_4 = requests.get(DomainURL,headers=headers,verify=False)
    
    if (response_4.status_code)==200:
        domdata=response_4.json()
       
        for l in domdata:
          if int(l['id'])==int(did):


             print("Domain Id:",did," Client from MTU:", l['name'])
             return(l['name'])
       
    else:
       return(ClientName) 
    
        
             

def OffenseType(ClientIP,ClientApi,offense_type):
    OffenseTypeURL=str(ClientIP+'api/siem/offense_types').strip()
    headers = {'accept': 'application/json', 'SEC':str(ClientApi),'range':'all'}

    response_5 = requests.get(OffenseTypeURL,headers=headers,verify=False)


    #print(response_5.status_code) 
    if response_5.status_code ==200:
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
        headers = {'accept': 'application/json', 'SEC':str(ClientApi),'range':'items=0-5'}
        #print(headers)
        url=str(str(ClientIP)+'api/siem/offenses?fields=id%2Cstatus%2Cdescription%2Coffense_type%2Coffense_source%2Cmagnitude%2Csource_network%2Cdestination_networks%2Cassigned_to%2Cstart_time%2Cevent_count%2Cdomain_id%2Cfollow_up%2Ccategories%2Cseverity%2Cinactive')
        #print(url)




        #response_1 = session.get(url,headers=headers,verify=False)
        #session.resolve_redirects(response_1,response_1.request)
        session = requests.session()
        session.max_redirects = 1000
        session.mount(url,HTTPAdapter(max_retries=1))
        try:

            response_1 = session.get(url, headers=headers, verify=False,timeout=(2,5))
        except Timeout:
            success = 'False'
            response = 'Timeout'
            return (success, response)
        except ConnectionError as ce:
            print('connection_error:', ce)
            success = 'False'
            response = 'ConnectionError'
            return (success, response)
        except Exception as e:
            trace_back = sys.exc_info()[2]
            line = trace_back.tb_lineno
            p= ("Process Exception in line {}".format(line), e)

            print(str(p))

            success='False'
            response='fail'
            return(success,response)

        if (response_1.status_code) == 200 or response_1.status_code== 206:
            print(ClientName, "RESPONSE 1 CODE: ", response_1.status_code)
            data = response_1.json()
            last_id = str(data[0]['id'])
            print(ClientName,"last id from qradar:",last_id,"last recorded id:",lof)
            rangecheck = int(last_id)-int(lof)

            if rangecheck>=5 and int(lof)!=0:
                headers = {'accept': 'application/json', 'SEC':str(ClientApi), 'Version': '12.0','range':str('items=0-'+str(rangecheck))}
                response_1 = session.get(url,headers=headers,verify=False)
                data = response_1.json()
                last_id = str(data[0]['id'])
                print("rangecheck true, range:", rangecheck)





            print('*******LOF=',lof)
            if lof=='0'or int(lof)==0 or lof=='#0':
                print("lof =0")
                last_line = int(last_id)-1
                col=[0,1,2,3,4,5,6,7,8]
                df=pd.read_csv('/home/qradar/Client.csv',usecols=col)
                df.iat[int(j),4]=str('#'+str(last_id))
                df.to_csv('/home/qradar/Client.csv',index=False)
                del df
                print(ClientName+", "+"File was empty. To avoid errors, the file has been updated with the ID of the penultimate QRadar offense: "+ str(last_line))
            #elif int(last_id)>int(lof):
            #last_line = int(lof)
            elif int(last_id)==int(lof):
                print("no new offense for: ",ClientName)
                return("NoNew",response_1.status_code)
            else:
                last_line=int(lof)
                col=[0,1,2,3,4,5,6,7,8]
                df=pd.read_csv('/home/qradar/Client.csv',usecols=col)
                df.iat[int(j),4]=str('#'+str(last_id))
                df.to_csv('/home/qradar/Client.csv',index=False)
                del df
            first_new_offense = int(last_line)
            diff = (int(last_id) - first_new_offense)

            #print("This is where lastline is compared to last_id",last_line,"  ",last_id)
            if diff>=0:
                print("Diff: ",diff, "Client : ", ClientName,"lastID: ",last_id,"last_line: ",last_line,"diff :",diff)
                col=[0,1,2,3,4,5,6,7,8]
                df=pd.read_csv('/home/qradar/Client.csv',usecols=col)
                df.iat[int(j),5]=str('#'+str(diff))
                df.to_csv('/home/qradar/Client.csv',index=False)
                del df
                for i in range(0,diff):

                    status=str(data[i]['status'])
                    inactive=str(data[i]['inactive'])
                    if status=='OPEN' or status=='HIDDEN':

                        if ClientIP!='https://'MultiTenant IP/':
                            customer = ClientName
                        elif ClientIP=='https://10.86.49.158/':
                            customer = DomainName(ClientIP,ClientApi,str(data[i]['domain_id']))
                        if ClientName =='staging' or ClientName =='Staging'or ClientName=='TestDomain' or ClientName =='Teset':
                            continue
                        print(ClientName,": i=",i)
                        offenseDescription = str(data[i]['description'])
                        offenseid = (str(data[i]['id']))
                        #("offenseID: ",offenseid,"customer: ",customer)
                        offensetype=OffenseType(ClientIP,ClientApi,str(data[i]['offense_type']))



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





                        customFields = CustomFieldHelper() \
                            .add_string('offenseid', (offenseid)) \
                            .add_string('offensetype',(offensetype)) \
                            .add_string('status',(status)) \
                            .add_integer('offensemagnitude',int(offenseMagnitude)) \
                            .add_string('categories',categories) \
                            .add_string('followup',followUp) \
                            .add_integer('offenseeventcount', int(offenseEventCount)) \
                            .add_string('offensesource', offenseSource) \
                            .add_string('offensesourcenetwork', offenseSourceNetwork) \
                            .add_string('offensedestinationnetworks', offenseDestinationNetworks) \
                            .add_string('reasonForClosing', "null") \
                            .add_string('assignedto',assignedTo) \
                            .add_integer('domainid',int(domainid)) \
                            .add_date('starttime',int(starttime)) \
                            .add_string('linktoqradar',LinkToQradar) \
                            .add_string('customer',customer) \
                            .add_string('inactive',inactive) \
                            .build()

                        if int(offenseMagnitude) < 5:
                            tlp = '1'
                        elif int(offenseMagnitude)>4 and int(offenseMagnitude)<8:
                            tlp = '2'
                        elif int(offenseMagnitude)>7 and int(offenseMagnitude)<10:
                            tlp= '3'
                        elif int(offenseMagnitude)==10:
                            tlp='4'
                        else:
                            tlp='2'

                        if int(offenseMagnitude) < 5:
                            sev = '1'
                        elif int(offenseMagnitude)>4 and int(offenseMagnitude)<8:
                            sev = '2'
                        elif int(offenseMagnitude)>7 and int(offenseMagnitude)<10:
                            sev = '3'
                        elif int(offenseMagnitude)==10:
                            sev = '4'
                        else:
                            sev = '2'
                        customer_tag = str("Client: "+ customer)
                        magnitude_tag = str("Mag: "+str(offenseMagnitude))
                        offense_type_tag =str("Off_Type: "+ str(offensetype))


                        case = Case(title=offenseDescription, id=offenseid,
                                    tlp=int(tlp),
                                    severity = int(sev),
                                    #flag=False,
                                    metrics=["offenseeventcount",int(offenseEventCount)],
                                    tags=[customer_tag ,magnitude_tag,offense_type_tag],
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
                            df.iat[j,7] =str("Case Error: "+ str(response_2.status_code))
                            df.to_csv('Client.csv',index=False)
                            del df
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

                    else:
                        continue
                return('True',response_1.status_code)

            else:
                return("NoNew",response_1.status_code)

        else:
            print("Can't get offenses, check the configuration.")
            #pass
            return('False',response_1.status_code)



def client_process(j):
   
      col=[0,1,2,3,4,5,6,7,8] 
      df=pd.read_csv('/home/qradar/Client.csv',usecols=col,index_col=False)
      process_id = current_process().name
      print(f"process ID: {process_id}")
      ClientName=df.values[j][0]
      ClientIP=df.values[j][1]
      ClientApi=df.values[j][2]
      ClientIP=ClientIP.strip()
      ClientName=ClientName.strip()
      ClientApi=ClientApi.strip()
      lofs= df['Last_offense'].str.split('#').str[1]

      lof=int(lofs.values[j])
      #print(lof)
      starttime1=time.process_time()
      df.iat[j,8]=str(pd.to_datetime(time.time(), unit='s'))
      df.to_csv('/home/qradar/Client.csv',index=False)
      del df
      
    
    
        			
      warnings.filterwarnings('ignore')
				
      #print("sent to Request:",ClientName,ClientIP,ClientApi,lof,j)
      
      #try:
      success,response = OffensesRequest(ClientName,ClientIP,ClientApi,lof,j)

      # except Exception as e:
      #       trace_back = sys.exc_info()[2]
      #       line = trace_back.tb_lineno
      #       p= ("Process Exception in line {}".format(line), e)
      #
      #       print(str(p))
      #       logf = open('Hive.log','a')
      #       logf.writelines(str(p))
      #       logf.close()
      #       success='False'
      #       response=p
      #       stoptime1 = time.process_time()
      #       client_time = stoptime1 - starttime1
      #       print(ClientName, success,p,stoptime1,client_time)
      #       col = [0, 1, 2, 3, 4, 5, 6, 7, 8]
      #       df = pd.read_csv('Client.csv', usecols=col, index_col=False)
      #       df.iat[j, 3] = 'Fail'
      #       #df.iat[j, 7] = response
      #       df.iat[j, 6] = str(client_time)
      #       df.to_csv('/home/qradar/Client.csv', index=False)
      #       del df
      #       pass

      #success,response = OffensesRequest(ClientName,ClientIP,ClientApi,lof,j)
      print(success,response) 
      if success=='True':
         stoptime1=time.process_time()
         client_time =stoptime1-starttime1
         print(ClientName,'Success',stoptime1,client_time)
         print('**********************************************************************************')
         col=[0,1,2,3,4,5,6,7,8] 
         df=pd.read_csv('/home/qradar/Client.csv',usecols=col,index_col=False)
         df.iat[j,3]='Success'
         df.iat[j,6] = str(client_time)
         df.to_csv('/home/qradar/Client.csv',index=False)
         del df
         return()
      elif success=='False':
         stoptime1=time.process_time()
         client_time =stoptime1-starttime1
         print(ClientName,'Fail',stoptime1,client_time)
         print('**********************************************************************************')
         col=[0,1,2,3,4,5,6,7,8]
         df=pd.read_csv('Client.csv',usecols=col,index_col=False)
         df.iat[j,3]='Fail'
         #df.iat[j,7]=response
         df.iat[j,6]=str(client_time)
         df.to_csv('/home/qradar/Client.csv',index=False)
         del df
         return()
      elif  success=='NoNew':
         stoptime1=time.process_time()
         client_time =stoptime1-starttime1
         print(ClientName,'NoNew',stoptime1,client_time)
         print('**********************************************************************************')
         col=[0,1,2,3,4,5,6,7,8]
         df=pd.read_csv('/home/qradar/Client.csv',usecols=col,index_col=False)
         df.iat[j,3]='NoNew'
         df.iat[int(j),5]=str('#'+'0')
         df.iat[j,6]=str(client_time)
         df.to_csv('/home/qradar/Client.csv',index=False)
         del df
         return()
    

def method_process():
    print("method: Multi Process")
    col=[0,1,2,3,4,5,6,7,8] 
    df=pd.read_csv('/home/qradar/Client.csv',usecols=col,index_col=False)
    pend=(df[df['Client_Name']=='eof'].index.values)

    processes = []
    r = range(0,int(pend))
    numbers=[*r]
    for j in numbers:
        if df.values[j][0]!='eof':
           process = Process(target=client_process,args = (j,))
           processes.append(process)
           process.start()
       
    for process in processes:
           process.join()
           process.close
    del df
    return()

def method_pool():
    print("method:Pool")	
    col=[0,1,2,3,4,5,6,7,8] 
    df=pd.read_csv('/home/qradar/Client.csv',usecols=col,index_col=False)
    pend=(df[df['Client_Name']=='eof'].index.values)

    r = range(0,int(pend))
    numbers=[*r]
    with get_context("spawn").Pool() as p:
          #p=Pool()
          p.map(client_process,numbers)
          p.close()
          p.join()
    del df
    return()
   

def method_no_multi():
    global result
    print("Method: No-MultiProcess")
    col=[0,1,2,3,4,5,6,7,8] 
    df=pd.read_csv('/home/qradar/Client.csv',usecols=col,index_col=False)                                                                                                         
    pend=(df[df['Client_Name']=='eof'].index.values)

    r = range(0,int(pend))
    numbers=[*r]
    for j in numbers:
         if df.values[j][0]!='eof':
           result=client_process(j)

         elif df.values[j][0]=='eof':
            del df
            return()
    return()
    
def clean_csv():
    col=[0,1,2,3,4,5,6,7,8] 
    df=pd.read_csv('/home/qradar/Client.csv',usecols=col,index_col=False)                                                                                                         
    
    r = range(1,len(df))
    numbers=[*r]
    df2={'Client_Name':'eof'}
    for j in numbers:
         if df.values[j][0]=='eof':
             if j == len(df):
               df.drop(j,axis=0,inplace=True)
               df=df.append(df2,ignore_index=True)
               
               df.to_csv('/home/qradar/Client.csv',index=False)
               del df
               del df2
             elif j< len(df):
               diff=len(df)-j
               for i in range(diff,0,-1):
                   k=j+i
                   print(k)
                   print(df.iloc[[k-1]])
                   df.drop(k-1,axis=0,inplace=True)
               df=df.append(df2,ignore_index=True)               
               df.to_csv('/home/qradar/Client.csv',index=False)
               del df
               del df2
               break

         else:
             continue

    return() 
 


			   
            
if __name__ == '__main__': 
    #SELECT WHICH PROCESS YOU WANT TO RUN BY REMOVING THE '#' IN FRONT OF IT.mAKE SUR THE OTHER TWO HAVE A '#'.   
    tmain_start=time.perf_counter()
    clean_csv()

    method_no_multi()
    #method_pool()
    #method_process()
            

    tmain_stop=time.perf_counter()
    print(str(pd.to_datetime(time.time(), unit='s'))) 
    print("The time difference is :", tmain_stop-tmain_start)
    print('######################################################################')
    
    sys.exit()
    #df.iat[0,6]=timeit.default_timer() - starttime
    #df.to_csv('/home/qradar/Client.csv',index=False)
    
