rule cachedump_RID2ABB : DEMO EXE FILE HKTL {
   meta:
      description = "Detects a tool used by APT groups - from files cachedump_RID2ABB.exe, cachedump_RID2ABB64.exe"
      author = "Florian Roth"
      reference = "https://community.broadcom.com/home"
      date = "2016-09-08 08:03:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "cf58ca5bf8c4f87bb67e6a4e1fb9e8bada50157dacbd08a92a4a779e40d569c4"
      hash2 = "e38edac8c838a043d0d9d28c71a96fe8f7b7f61c5edf69f1ce0c13e141be281f"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Failed to open key SECURITY\\Cache in RegOpenKeyEx. Is service running as SYSTEM ? Do you ever log on domain ? " fullword ascii
      $s2 = "Unable to open LSASS.EXE process" fullword ascii
      $s3 = "Service not found. Installing CacheDump Service (%s)" fullword ascii
      $s4 = "CacheDump service successfully installed." fullword ascii
      $s5 = "Kill CacheDump service (shouldn't be used)" fullword ascii
      $s6 = "cacheDump [-v | -vv | -K]" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 3 of them )
}