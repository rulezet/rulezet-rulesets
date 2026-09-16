rule MAL_BurningUmbrella_Sample_6_RID31A9 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "49ef2b98b414c321bcdbab107b8fa71a537958fe1e05ae62aaa01fe7773c3b4b"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ExecuteFile=\"hidcon:nowait:\\\"Word\\\\r.bat\\\"\"" fullword ascii
      $s2 = "InstallPath=\"%Appdata%\\\\Microsoft\"" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}