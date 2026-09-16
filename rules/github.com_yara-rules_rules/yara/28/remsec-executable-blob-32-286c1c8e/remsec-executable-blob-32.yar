rule remsec_executable_blob_32
    {
        meta:
            author = "remsec"
 strings:
     $code = { 31 06 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 F0 }  
 condition:
         all of them
 }