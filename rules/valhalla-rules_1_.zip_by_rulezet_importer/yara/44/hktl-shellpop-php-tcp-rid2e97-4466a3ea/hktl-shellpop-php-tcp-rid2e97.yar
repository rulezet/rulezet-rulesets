rule HKTL_shellpop_PHP_TCP_RID2E97 : DEMO HKTL SCRIPT T1505_003 {
   meta:
      description = "Detects malicious PHP shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 11:21:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0412e1ab9c672abecb3979a401f67d35a4a830c65f34bdee3f87e87d060f0290"
      tags = "DEMO, HKTL, SCRIPT, T1505_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "php -r \"\\$sock=fsockopen" ascii
      $x2 = ";exec('/bin/sh -i <&3 >&3 2>&3');\"" ascii
   condition: 
      filesize < 3KB and all of them
}