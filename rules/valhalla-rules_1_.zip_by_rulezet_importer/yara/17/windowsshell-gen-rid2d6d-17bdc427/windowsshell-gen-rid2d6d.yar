rule WindowsShell_Gen_RID2D6D : DEMO EXE FILE GEN MAL SCRIPT {
   meta:
      description = "Detects simple Windows shell - from files keygen.exe, s1.exe, s2.exe, s3.exe, s4.exe"
      author = "Florian Roth"
      reference = "https://github.com/odzhan/shells/"
      date = "2016-03-26 10:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7c3d85eabac01e7a7ec914477ea9f17e3020b3b2f8584a46a98eb6a2a7611c5"
      hash2 = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
      hash3 = "df0693caae2e5914e63e9ee1a14c1e9506f13060faed67db5797c9e61f3907f0"
      tags = "DEMO, EXE, FILE, GEN, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "[ %c%c requires parameter" fullword ascii
      $s1 = "[ %s : %i" fullword ascii
      $s2 = "[ %s : %s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 175KB and 2 of them ) or ( all of them )
}