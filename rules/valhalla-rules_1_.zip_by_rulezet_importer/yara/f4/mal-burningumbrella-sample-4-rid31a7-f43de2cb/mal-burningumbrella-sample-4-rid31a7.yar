import "pe"
rule MAL_BurningUmbrella_Sample_4_RID31A7 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a1629e8abce9d670fdb66fa1ef73ad4181706eefb8adc8a9fd257b6a21be48c6"
      tags = "APT, DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $x1 = "dumpodbc.exe" fullword ascii
      $x2 = "photo_Bundle.exe" fullword ascii
      $x3 = "Connect 2 fails : %d,%s:%d" fullword ascii
      $x4 = "Connect fails 1 : %d %s:%d" fullword ascii
      $x5 = "New IP : %s,New Port: %d" fullword ascii
      $x6 = "Micrsoft Corporation. All rights reserved." fullword wide
      $x7 = "New ConFails : %d" fullword ascii
      $s1 = "cmd /c net stop stisvc" fullword ascii
      $s2 = "cmd /c net stop spooler" fullword ascii
      $s3 = "\\temp\\s%d.dat" ascii
      $s4 = "cmd /c net stop wuauserv" fullword ascii
      $s5 = "User-Agent: MyApp/0.1" fullword ascii
      $s6 = "%s->%s Fails : %d" fullword ascii
      $s7 = "Enter WorkThread,Current sock:%d" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and ( ( pe.exports ( "Print32" ) and 2 of them ) or 1 of ( $x* ) or 4 of them )
}