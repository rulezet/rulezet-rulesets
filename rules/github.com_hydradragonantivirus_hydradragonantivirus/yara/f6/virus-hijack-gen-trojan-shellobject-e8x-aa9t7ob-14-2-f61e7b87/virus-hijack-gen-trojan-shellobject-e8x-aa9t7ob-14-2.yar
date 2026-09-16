rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73e7afa80c27ea5ecaaea5707722b48f832aa221e7d220ce227c3a085881a79d"

  strings:
    $s1  = "=Error decoding URL style (%%XX) encoded string at position %d1Invalid URL encoded character (%s) at position %dMust wait on at" wide
    $s2  = "support@wisecleaner.com" fullword ascii
    $s3  = "Unknown credentials use!Do AcquireCredentialsHandle first\"CompleteAuthToken is not supported\"'%s' is not a valid property valu" wide
    $s4  = "OLE control activation failed*Could not obtain OLE control window handle%License information for %s is invalidPLicense informati" wide
    $s5  = "Default+Operation not supported on selected printer.There is no default printer currently selected/Menu '%s' is already being us" wide
    $s6  = "Invalid argument/Index out of range (%d).  Must be >= 0 and < %d8String index out of range (%d).  Must be >= %d and <= %drHigh s" wide
    $s7  = "form logo" fullword ascii
    $s8  = "8Please input your license key to active the PRO version." fullword ascii
    $s9  = "Inappropriate BackendjThis \"Portable Network Graphics\" image is not valid because it contains invalid pieces of data (crc erro" wide
    $s10 = "Invalid stream operationoThe \"Portable Network Graphics\" could not be created because invalid image type parameters have being" wide
    $s11 = "Duplicates not allowed5Insufficient RTTI available to support this operation The specified path was not found The path format is" wide
    $s12 = "Timespan too longbThe duration cannot be returned because the absolute value exceeds the value of TTimeSpan.MaxValue$Operation n" wide
    $s13 = "Button Support" fullword ascii
    $s14 = "*Move the selected items to the Recycle Bin" fullword ascii
    $s15 = "!Have troubling input license key?" fullword ascii
    $s16 = "scan ani" fullword ascii
    $s17 = "@You might be losing the priviledges of Pro version enjoying now." fullword ascii
    $s18 = " 2006-2020 WiseCleaner.All rights reserved." fullword ascii
    $s19 = "Error parsing SVG Text: %s" fullword wide
    $s20 = "Error: Tag \"svg\" not found." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}