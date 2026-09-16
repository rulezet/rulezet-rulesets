rule Codoso_PlugX_2_RID2C58 : DEMO EXE G0073 MAL plugx {
   meta:
      description = "Detects Codoso APT PlugX Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 09:45:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, G0073, MAL, plugx"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%TEMP%\\HID" fullword wide
      $s2 = "%s\\hid.dll" fullword wide
      $s3 = "%s\\SOUNDMAN.exe" fullword wide
      $s4 = "\"%s\\SOUNDMAN.exe\" %d %d" fullword wide
      $s5 = "%s\\HID.dllx" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 3 of them ) or all of them
}