rule CN_Honker_IIS_logcleaner1_0_readme_RID33B4 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file readme.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:59:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "LogCleaner.exe <ip> [Logpath]" fullword ascii
      $s3 = "http://l-y.vicp.net" fullword ascii
   condition: 
      filesize < 7KB and all of them
}