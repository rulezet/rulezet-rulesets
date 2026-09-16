rule WAF_Bypass_RID2AC0 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file WAF-Bypass.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:11:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Email: blacksplitn@gmail.com" fullword wide
      $s2 = "User-Agent:" fullword wide
      $s3 = "Send Failed.in RemoteThread" fullword ascii
      $s4 = "www.example.com" fullword wide
      $s5 = "Get Domain:%s IP Failed." fullword ascii
      $s6 = "Connect To Server Failed." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 7992KB and 5 of them
}