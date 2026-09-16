rule Misdat_Backdoor
{
   
   meta:
        author = "Cylance SPEAR Team"
        
    
    strings:
        $imul = {03 45 F8 69 C0 D9 DB 00 00 05 3B DA 00 00}
        $delphi = {50 45 00 00 4C 01 08 00 19 5E 42 2A}
        
    condition:
        $imul and $delphi
}