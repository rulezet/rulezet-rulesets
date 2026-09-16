rule SLServer_campaign_code
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the related campaign code."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $campaign = "wthkdoc0106"
        
    condition:
                uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $campaign
}