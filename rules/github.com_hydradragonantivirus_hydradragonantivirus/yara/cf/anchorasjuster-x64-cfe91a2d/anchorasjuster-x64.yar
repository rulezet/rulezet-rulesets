import "pe"
rule anchorAsjuster_x64 {
  meta:
    description = "files - file anchorAsjuster_x64.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-02-22"
    hash1       = "3ab8a1ee10bd1b720e1c8a8795e78cdc09fec73a6bb91526c0ccd2dc2cfbc28d"

  strings:
    $s1  = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
    $s2  = "anchorAdjuster* --source=<source file> --target=<target file> --domain=<domain name> --period=<recurrence interval, minutes, def" ascii
    $s3  = "anchorAdjuster* --source=<source file> --target=<target file> --domain=<domain name> --period=<recurrence interval, minutes, def" ascii
    $s4  = "target file \"%s\"" fullword ascii
    $s5  = "--target=" fullword ascii
    $s6  = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
    $s7  = "error write file, written %i bytes, need write %i bytes, error code %i" fullword ascii
    $s8  = "error create file \"%s\", code %i" fullword ascii
    $s9  = "guid: %s, shift 0x%08X(%i)" fullword ascii
    $s10 = "ault value 15> -guid --count=<count of instances>" fullword ascii
    $s11 = "domain: shift 0x%08X(%i)" fullword ascii
    $s12 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
    $s13 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii
    $s14 = "wrong protocol type" fullword ascii  
    $s15 = "network reset" fullword ascii  
    $s16 = "owner dead" fullword ascii  
    $s17 = "connection already in progress" fullword ascii  
    $s18 = "network down" fullword ascii  
    $s19 = "protocol not supported" fullword ascii  
    $s20 = "connection aborted" fullword ascii  

  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and
    (pe.imphash() == "9859b7a32d1227be2ca925c81ae9265e" and 8 of them)
}