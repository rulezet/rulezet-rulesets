rule APT_EQGRP_workit_RID2CD3 : APT DEMO SCRIPT T1105 {
   meta:
      description = "EQGRP Toolset Firewall - file workit.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:05:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"
      tags = "APT, DEMO, SCRIPT, T1105"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "macdef init > /tmp/.netrc;" fullword ascii
      $s2 = "/usr/bin/wget http://" ascii
      $s3 = "HOME=/tmp ftp" fullword ascii
      $s4 = " >> /tmp/.netrc;" fullword ascii
      $s5 = "/usr/rapidstream/bin/tftp" fullword ascii
      $s6 = "created shell_command:" fullword ascii
      $s7 = "rm -f /tmp/.netrc;" fullword ascii
      $s8 = "echo quit >> /tmp/.netrc;" fullword ascii
      $s9 = "echo binary >> /tmp/.netrc;" fullword ascii
      $s10 = "chmod 600 /tmp/.netrc;" fullword ascii
      $s11 = "created cli_command:" fullword ascii
   condition: 
      6 of them
}