rule HKTL_hkdoordll_RID2C66 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file hkdoordll.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is" 
   condition: 
      all of them
}