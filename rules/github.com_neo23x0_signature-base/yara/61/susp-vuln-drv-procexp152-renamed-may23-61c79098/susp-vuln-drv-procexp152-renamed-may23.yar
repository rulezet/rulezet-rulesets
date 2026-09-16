rule SUSP_VULN_DRV_PROCEXP152_Renamed_May23 {
   meta:
      description = "Detects vulnerable process explorer driver (original file name: PROCEXP152.SYS) that has been renamed (often used by attackers to elevate privileges)"
      author = "Florian Roth"
      reference = "https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/"
      date = "2023-05-05"
      score = 70
      hash1 = "cdfbe62ef515546f1728189260d0bdf77167063b6dbb77f1db6ed8b61145a2bc"
      id = "af2ec5d5-3453-5d35-8d19-4f37c61fabce"
   strings:
      $a1 = "\\ProcExpDriver.pdb" ascii
      $a2 = "\\Device\\PROCEXP152" wide fullword
      $a3 = "procexp.Sys" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 200KB 
      and all of them
      and not filename matches /PROCEXP152\.SYS/i
}