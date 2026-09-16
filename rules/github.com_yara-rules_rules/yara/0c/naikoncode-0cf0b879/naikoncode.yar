rule NaikonCode : Naikon Family 
{
    meta:
        description = "Naikon code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
    
    strings:
                $ = { 0F AF C1 C1 E0 1F }         $ = { 35 5A 01 00 00}         $ = { 81 C2 7F 14 06 00 }     
    condition:
        all of them
}