rule CN_Honker_Alien_command_RID2FEE : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file command.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:18:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "for /d %i in (E:\\freehost\\*) do @echo %i" fullword ascii
      $s1 = "/c \"C:\\windows\\temp\\cscript\" C:\\windows\\temp\\iis.vbs" fullword ascii
   condition: 
      filesize < 8KB and all of them
}