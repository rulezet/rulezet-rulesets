rule CN_Honker_Webshell_cfm_list_RID31AD : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file list.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:32:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii
      $s2 = "<TD>#mydirectory.size#</TD>" fullword ascii
   condition: 
      filesize < 10KB and all of them
}