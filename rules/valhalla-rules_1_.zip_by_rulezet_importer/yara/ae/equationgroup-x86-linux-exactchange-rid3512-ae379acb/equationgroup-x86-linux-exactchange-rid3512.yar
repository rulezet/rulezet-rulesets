rule EquationGroup_x86_linux_exactchange_RID3512 : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 15:57:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
      hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "kernel has 4G/4G split, not exploitable" fullword ascii
      $x2 = "[+] kernel stack size is %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 1000KB and 1 of them )
}