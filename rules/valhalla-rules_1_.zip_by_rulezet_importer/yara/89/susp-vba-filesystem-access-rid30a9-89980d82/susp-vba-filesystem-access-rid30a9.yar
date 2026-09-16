rule SUSP_VBA_FileSystem_Access_RID30A9 : DEMO FILE SCRIPT SUSP {
   meta:
      description = "Detects suspicious VBA that writes to disk and is activated on document open"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-06-21 12:49:21"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2021-01-15"
      hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
      tags = "DEMO, FILE, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Common Files\\Microsoft Shared\\" wide
      $s2 = "Scripting.FileSystemObject" ascii
      $a1 = "Document_Open" ascii
      $a2 = "WScript.Shell" ascii
      $a3 = "AutoOpen" fullword ascii
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 100KB and all of ( $s* ) and 1 of ( $a* )
}