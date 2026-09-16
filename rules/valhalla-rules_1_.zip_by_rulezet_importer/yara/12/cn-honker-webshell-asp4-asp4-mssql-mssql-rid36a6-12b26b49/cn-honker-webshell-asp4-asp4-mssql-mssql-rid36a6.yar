rule CN_Honker_Webshell__asp4_asp4_MSSQL__MSSQL__RID36A6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files asp4.txt, asp4.txt, MSSQL_.asp, MSSQL_.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:04:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "7097c21f92306983add3b5b29a517204cd6cd819"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\"<form name=\"\"searchfileform\"\" action=\"\"?action=searchfile\"\" method=\"" ascii
      $s1 = "\"<TD ALIGN=\"\"Left\"\" colspan=\"\"5\"\">[\"& DbName & \"]" fullword ascii
      $s2 = "Set Conn = Nothing " fullword ascii
   condition: 
      filesize < 341KB and all of them
}