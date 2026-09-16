rule SLServer_unknown_string
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for a unique string."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $string = "test-b7fa835a39"
        
    condition:
                uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $string
}