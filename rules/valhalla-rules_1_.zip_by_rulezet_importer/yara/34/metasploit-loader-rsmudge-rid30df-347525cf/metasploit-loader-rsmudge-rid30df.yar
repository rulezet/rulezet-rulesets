rule Metasploit_Loader_RSMudge_RID30DF : DEMO EXE FILE METASPLOIT SUSP {
   meta:
      description = "Detects a Metasploit Loader by RSMudge - file loader.exe"
      author = "Florian Roth"
      reference = "https://github.com/rsmudge/metasploit-loader"
      date = "2016-04-20 12:58:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "afe34bfe2215b048915b1d55324f1679d598a0741123bc24274d4edc6e395a8d"
      tags = "DEMO, EXE, FILE, METASPLOIT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Could not resolve target" fullword ascii
      $s2 = "Could not connect to target" fullword ascii
      $s3 = "%s [host] [port]" fullword ascii
      $s4 = "ws2_32.dll is out of date." fullword ascii
      $s5 = "read a strange or incomplete length value" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( 3 of ( $s* ) ) ) or ( all of them )
}