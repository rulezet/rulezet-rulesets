import "pe"
rule ZXshell_20171211_chrsben_RID2F0D : DEMO EXE FILE MAL zxshell {
   meta:
      description = "Detects ZxShell variant surfaced in Dec 17"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/#/file/dd01e7a1c9b20d36ea2d961737780f2c0d56005c370e50247e38c5ca80dcaa4f/detection"
      date = "2017-12-11 11:40:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "dd01e7a1c9b20d36ea2d961737780f2c0d56005c370e50247e38c5ca80dcaa4f"
      tags = "DEMO, EXE, FILE, MAL, zxshell"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $x1 = "ncProxyXll" fullword ascii
      $s1 = "Uniscribe.dll" fullword ascii
      $s2 = "GetModuleFileNameDll" fullword ascii
      $s4 = "$Hangzhou Shunwang Technology Co.,Ltd0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and ( pe.imphash ( ) == "de481441d675e9aca4f20bd8e16a5faa" or pe.exports ( "PerfectWorld" ) or pe.exports ( "ncProxyXll" ) or 1 of ( $x* ) or 2 of them )
}