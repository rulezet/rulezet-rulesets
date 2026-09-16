import "pe"
rule Foudre_Backdoor_Component_1_RID319C : DEMO EXE FILE MAL {
   meta:
      description = "Detects Foudre Backdoor"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2017/08/unit42-prince-persia-ride-lightning-infy-returns-foudre/"
      date = "2017-08-01 13:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "7c6206eaf0c5c9c6c8d8586a626b49575942572c51458575e51cba72ba2096a4"
      hash2 = "db605d501d3a5ca2b0e3d8296d552fbbf048ee831be21efca407c45bf794b109"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $s1 = { 50 72 6F 6A 65 63 74 31 2E 64 6C 6C 00 44 31 } 
      $s2 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" fullword wide
      $s3 = "C:\\Documents and Settings\\All Users\\" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and ( 3 of them ) or ( 2 of them and pe.exports ( "D1" ) ) )
}