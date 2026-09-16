rule sbin_squid_RID2B42 : APT CHINA DEMO SCRIPT T1007 {
   meta:
      description = "Chinese Hacktool Set - file squid.bat"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:58:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, SCRIPT, T1007"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "del /s /f /q" fullword ascii
      $s1 = "squid.exe -z" fullword ascii
      $s2 = "net start Squid" fullword ascii
      $s3 = "net stop Squid" fullword ascii
   condition: 
      filesize < 1KB and all of them
}