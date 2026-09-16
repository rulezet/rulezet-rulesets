rule BangatCode
{
    
    meta:
        description = "Bangat code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
                $ = { FE 4D ?? 8D 4? ?? 50 5? FF }
    
    condition:
        any of them
}