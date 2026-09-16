import "pe"
rule qbot_8734_payload_dll {
  meta:
    description = "files - file e2bc969424adc97345ac81194d316f58da38621aad3ca7ae27e40a8fae582987"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2022-02-20"
    hash1       = "e2bc969424adc97345ac81194d316f58da38621aad3ca7ae27e40a8fae582987"

  strings:
    $s1  = "Terfrtghygine.dll" fullword ascii
    $s2  = "Winamp can read extended metadata for titles. Choose when this happens:" fullword wide  
    $s3  = "Read metadata when file(s) are loaded into Winamp" fullword wide  
    $s4  = "Use advanced title formatting when possible" fullword wide  
    $s5  = "PQVW=!?" fullword ascii
    $s6  = "Show underscores in titles as spaces" fullword wide  
    $s7  = "Advanced title display format :" fullword wide  
    $s8  = "CreatePaint" fullword ascii
    $s9  = "PQRVW=2\"" fullword ascii
    $s10 = "Advanced Title Formatting" fullword wide  
    $s11 = "Read metadata when file(s) are played or viewed in the playlist editor" fullword wide  
    $s12 = "Show '%20's in titles as spaces" fullword wide  
    $s13 = "Example : \"%artist% - %title%\"" fullword wide  
    $s14 = "PQRVW=g" fullword ascii
    $s15 = "PQRW=e!" fullword ascii
    $s16 = "ATF Help" fullword wide  
    $s17 = "(this can be slow if a large number of files are added at once)" fullword wide  
    $s18 = "PQRVW=$" fullword ascii
    $s19 = "Metadata Reading" fullword wide  
    $s20 = "Other field names: %artist%, %album%, %title%, %track%, %year%, %genre%, %comment%, %filename%, %disc%, %rating%, ..." fullword wide  

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "aa8a9db10fba890f8ef9edac427eab82" and pe.exports("CreatePaint") or 8 of them)
}