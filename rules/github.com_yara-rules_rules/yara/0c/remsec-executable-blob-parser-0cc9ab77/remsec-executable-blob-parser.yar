rule remsec_executable_blob_parser
 {
     meta:
         author = "remsec"
     strings:
         $code ={ ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }
     condition:
         all of them
 }