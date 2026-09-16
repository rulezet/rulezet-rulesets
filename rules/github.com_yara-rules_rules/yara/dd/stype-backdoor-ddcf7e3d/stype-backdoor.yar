rule SType_Backdoor
{
   
    meta:
        author = "Cylance SPEAR Team"
        
        

    strings:
        $stype = "stype=info&data="
        $mmid = "?mmid="
        $status = "&status=run succeed"
        $mutex = "_KB10B2D1_CIlFD2C"
        $decode = {8B 1A 8A 1B 80 EB 02 8B 74 24 08 32 1E 8B 31 88 1E 8B 1A 43}
    
    condition:
        $stype or ($mmid and $status) or $mutex or $decode
}