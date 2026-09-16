rule HKTL_dbgntboot_RID2C66 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dbgntboot.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp" 
      $s3 = "sth junk the M$ Wind0wZ retur" 
   condition: 
      all of them
}