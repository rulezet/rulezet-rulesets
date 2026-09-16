rule MAL_BurningUmbrella_Sample_22_RID31D7 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:39:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "fa116cf9410f1613003ca423ad6ca92657a61b8e9eda1b05caf4f30ca650aee5"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" ascii
      $s3 = "Content-Disposition: form-data; name=\"txt\"; filename=\"" fullword ascii
      $s4 = "Fail To Enum Service" fullword ascii
      $s5 = "Host Power ON Time" fullword ascii
      $s6 = "%d Hours %2d Minutes %2d Seconds " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 4 of them
}