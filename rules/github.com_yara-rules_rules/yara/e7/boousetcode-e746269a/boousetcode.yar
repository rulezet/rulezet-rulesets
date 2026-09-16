rule BoousetCode
{
    
    meta:
        description = "Boouset code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $boousetdat = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }
        
    condition:
        any of them
}