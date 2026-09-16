rule remsec_encrypted_api
 {
     meta:
         author = "remsec"
     strings:
         $open_process ={ 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }  
 condition:  
   all of them  
 }