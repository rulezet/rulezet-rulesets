rule remsec_executable_blob_64
 {
     meta:
         author = "remsec"
     strings:
         $code = { 31 06 48 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 EF }
 condition:  
   all of them  
 }