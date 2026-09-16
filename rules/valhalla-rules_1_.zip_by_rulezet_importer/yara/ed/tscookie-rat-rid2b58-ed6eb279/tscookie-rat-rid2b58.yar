import "pe"
rule TSCookie_RAT_RID2B58 : DEMO EXE FILE MAL {
   meta:
      description = "Detects TSCookie RAT"
      author = "Florian Roth"
      reference = "http://blog.jpcert.or.jp/2018/03/malware-tscooki-7aa0.html"
      date = "2018-03-06 09:02:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2bd13d63797864a70b775bd1994016f5052dc8fd1fd83ce1c13234b5d304330d"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $x1 = "[-] DecryptPassword_Outlook failed(err=%d)" fullword ascii
      $x2 = "----------------------- Firefox Passwords ------------------" fullword ascii
      $x3 = "--------------- Outlook Passwords ------------------" fullword ascii
      $x4 = "----------------------- IE Passwords ------------------" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and ( ( pe.exports ( "DoWork" ) and pe.exports ( "PrintF" ) ) or 1 of them )
}