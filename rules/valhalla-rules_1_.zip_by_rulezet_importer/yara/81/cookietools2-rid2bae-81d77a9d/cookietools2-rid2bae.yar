rule CookieTools2_RID2BAE : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file CookieTools2_RID2BAE.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:16:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "www.gxgl.com&www.gxgl.net" fullword wide
      $s2 = "ip.asp?IP=" fullword ascii
      $s3 = "MSIE 5.5;" fullword ascii
      $s4 = "SOFTWARE\\Borland\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and all of them
}