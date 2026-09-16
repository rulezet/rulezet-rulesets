rule CN_Honker_mssqlpw_scan_RID2FE2 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file mssqlpw scan.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:16:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "response.Write(\"I Get it ! Password is <font color=red>\" & str & \"</font><BR>" ascii
      $s1 = "response.Write \"Done!<br>Process \" & tTime & \" s\"" fullword ascii
   condition: 
      filesize < 6KB and all of them
}