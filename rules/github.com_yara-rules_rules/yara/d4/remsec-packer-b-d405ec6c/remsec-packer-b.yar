rule remsec_packer_B
 {
 meta:
         author = "remsec"
 strings:
         $code ={ 00 00 48 8D ( 45 ?? | 84 24 ?? ?? 00 00 ) ( 44 88 6? 24 ?? | C6 44 24 ?? 00 ) 48 89 44 24 ?? 48 8D ( 45 ?? | 84 24 ?? ?? 00 00 ) C7 44 24 ?? 0? 00 00 00 2B ?8 48 89 ?C 24 ?? 44 89 6? 24 ?? 83 C? 08 89 ?C 24 ?? ( FF | 41 FF ) D? ( 05 | 8D 88 ) 00 00 00 3A }
 condition:
         all of them
 }