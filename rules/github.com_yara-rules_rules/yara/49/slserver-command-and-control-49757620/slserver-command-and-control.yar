rule SLServer_command_and_control
{
   
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the C2 server."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $c2 = "safetyssl.security-centers.com"
        
    condition:
                uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $c2
}