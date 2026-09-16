rule CN_Honker_Webshell_cfm_xl_RID30D5 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file xl.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:56:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input name=\"DESTINATION\" value=\"" ascii
      $s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x433c and filesize < 13KB and all of them
}