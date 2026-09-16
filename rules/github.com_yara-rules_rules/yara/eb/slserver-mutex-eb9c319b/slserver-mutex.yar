rule SLServer_mutex
{
    
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the mutex."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $mutex = "M&GX^DSF&DA@F"
        
    condition:
                uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $mutex
}