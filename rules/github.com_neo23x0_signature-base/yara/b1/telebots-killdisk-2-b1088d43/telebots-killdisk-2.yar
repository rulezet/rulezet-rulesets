rule TeleBots_KillDisk_2 {
   meta:
      description = "Detects TeleBots malware - KillDisk"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "26173c9ec8fd1c4f9f18f89683b23267f6f9d116196ed15655e9cb453af2890e"
      id = "7797187f-c94b-5323-ae43-2dc001f0b481"
   strings:
      $s1 = "Plug-And-Play Support Service" fullword wide
      $s2 = " /c \"echo Y|" fullword wide
      $s3 = "%d.%d.%d#%d:%d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}