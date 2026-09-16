import "pe"
rule SentinelLabs_SUPERNOVA
{
    meta:
        description = "Identifies potential versions of App_Web_logoimagehandler.ashx.b6031896.dll weaponized with SUPERNOVA"
        date = "2020-12-22"
        author = "SentinelLabs"
        source = "https://labs.sentinelone.com/solarwinds-understanding-detecting-the-supernova-webshell-trojan/"
        
    strings:
        $ = "clazz"
        $ = "codes"
        $ = "args"
        $ = "ProcessRequest"
        $ = "DynamicRun"
        $ = "get_IsReusable"
        $ = "logoimagehandler.ashx" wide
        $ = "SiteNoclogoImage" wide
        $ = "SitelogoImage" wide

    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and pe.imports("mscoree.dll")) and all of them
}