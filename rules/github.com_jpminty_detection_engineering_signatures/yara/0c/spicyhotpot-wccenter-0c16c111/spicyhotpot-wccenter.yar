rule SpicyHotPot_wccenter {
   meta:
      description = "SpicyHotPot - wccenter.exe: Used to identify malware that communicates with the rootkit component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "17095beda4afeabb7f41ff07cf866ddc42e49da1a4ed64b9c279072caab354f6"
   strings:
      $x1 = "D:\\Work\\Install_Driver\\Driver_helper\\Release\\wccenter.pdb" fullword ascii
      $x2 = "wdlogin.exe" fullword wide
      $x3 = "wuhost.exe" fullword wide
      $x4 = "wrme.exe" fullword wide
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "&Beijing JoinHope Image Technology Ltd.1/0-" fullword ascii
      $s4 = "operator co_await" fullword ascii
      $s5 = "&Beijing JoinHope Image Technology Ltd.0" fullword ascii
      $s6 = "RvVersion" fullword wide
      $s7 = " Class Hierarchy Descriptor'" fullword ascii
      $s8 = "Base Class Descriptor" ascii
      $s9 = "Beijing1" fullword ascii
      $s10 = " Complete Object Locator'" fullword ascii
condition:
   uint16(0) == 0x5a4d and filesize < 400KB and 2 of ($x*) and 4 of ($s*)
}