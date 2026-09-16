rule MAL_PoisonIvy_Generic_3_RID2FA8 : DEMO EXE FILE GEN MAL {
   meta:
      description = "PoisonIvy RAT Generic Rule"
      author = "Florian Roth"
      reference = "-"
      date = "2015-05-14 12:06:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, GEN, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $k1 = "Tiger324{" fullword ascii
      $s2 = "WININET.dll" fullword ascii
      $s3 = "mscoree.dll" fullword wide
      $s4 = "WS2_32.dll" fullword
      $s5 = "Explorer.exe" fullword wide
      $s6 = "USER32.DLL" 
      $s7 = "CONOUT$" 
      $s8 = "login.asp" 
      $h1 = "HTTP/1.0" 
      $h2 = "POST" 
      $h3 = "login.asp" 
      $h4 = "check.asp" 
      $h5 = "result.asp" 
      $h6 = "upload.asp" 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( $k1 or all of ( $s* ) or all of ( $h* ) )
}