rule Codoso_PlugX_3_RID2C59 : DEMO EXE FILE G0073 MAL plugx {
   meta:
      description = "Detects Codoso APT PlugX Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 09:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G0073, MAL, plugx"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s2 = "mcs.exe" fullword ascii
      $s3 = "McAltLib.dll" fullword ascii
      $s4 = "WinRAR self-extracting archive" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1200KB and all of them
}