rule TeleBots_KillDisk_2_RID2E3A : APT DEMO EXE FILE G0034 {
   meta:
      description = "Detects TeleBots malware - KillDisk"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/"
      date = "2016-12-14 11:05:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "26173c9ec8fd1c4f9f18f89683b23267f6f9d116196ed15655e9cb453af2890e"
      tags = "APT, DEMO, EXE, FILE, G0034"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Plug-And-Play Support Service" fullword wide
      $s2 = " /c \"echo Y|" fullword wide
      $s3 = "%d.%d.%d#%d:%d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them )
}