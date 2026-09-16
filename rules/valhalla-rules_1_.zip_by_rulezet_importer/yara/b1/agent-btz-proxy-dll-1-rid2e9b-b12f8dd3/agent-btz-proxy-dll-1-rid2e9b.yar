import "pe"
rule Agent_BTZ_Proxy_DLL_1_RID2E9B : DEMO EXE FILE MAL T1090 {
   meta:
      description = "Detects Agent-BTZ Proxy DLL - activeds.dll"
      author = "Florian Roth"
      reference = "http://www.intezer.com/new-variants-of-agent-btz-comrat-found/"
      date = "2017-08-07 11:21:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c163c3f2bd5c5181147c6f4cf2571160197de98f496d16b38c7dc46b5dc1426"
      hash2 = "628d316a983383ed716e3f827720915683a8876b54677878a7d2db376d117a24"
      tags = "DEMO, EXE, FILE, MAL, T1090"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Modules" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them and pe.exports ( "Entry" ) )
}