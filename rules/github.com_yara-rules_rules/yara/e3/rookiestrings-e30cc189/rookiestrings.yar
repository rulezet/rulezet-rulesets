rule RookieStrings : Rookie Family
{
    meta:
        description = "Rookie Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "RookIE/1.0"
        
    condition:
       any of them
}