import "pe"
rule MAL_BurningUmbrella_Sample_18_RID31DC : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:40:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d8df60524deb6df4f9ddd802037a248f9fbdd532151bb00e647b233e845b1617"
      hash2 = "c55cb6b42cfabf0edf1499d383817164d1b034895e597068e019c19d787ea313"
      hash3 = "32144ba8370826e069e5f1b6745a3625d10f50a809f3f2a72c4c7644ed0cab03"
      tags = "APT, DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $s1 = "c:\\tmp\\tran.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( pe.imphash ( ) == "11675b4db0e7df7b29b1c1ef6f88e2e1" or pe.imphash ( ) == "364e1f68e2d412db34715709c68ba467" or pe.exports ( "deKernel" ) or 1 of them )
}