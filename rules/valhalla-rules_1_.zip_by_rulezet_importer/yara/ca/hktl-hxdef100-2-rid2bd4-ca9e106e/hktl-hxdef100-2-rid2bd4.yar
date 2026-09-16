rule HKTL_hxdef100_2_RID2BD4 : DEMO HKTL T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file hxdef100.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:23:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\\\.\\mailslot\\hxdef-rkc000" 
      $s2 = "Shared Components\\On Access Scanner\\BehaviourBlo" 
      $s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" 
   condition: 
      all of them
}