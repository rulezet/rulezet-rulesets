rule HKTL_hxdef100_RID2B43 : DEMO HKTL T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file hxdef100.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 08:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "RtlAnsiStringToUnicodeString" 
      $s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" 
      $s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH" 
   condition: 
      all of them
}