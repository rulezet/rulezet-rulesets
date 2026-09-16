rule EXPL_GitLab_CE_RCE_CVE_2021_22205_RID30B7 : CVE_2021_22205 DEMO EXPLOIT {
   meta:
      description = "Detects signs of exploitation of GitLab CE CVE-2021-22205"
      author = "Florian Roth"
      reference = "https://security.humanativaspa.it/gitlab-ce-cve-2021-22205-in-the-wild/"
      date = "2021-10-26 12:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_22205, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "VXNlci5maW5kX2J5KHVzZXJuYW1l" ascii
      $sa2 = "VzZXIuZmluZF9ieSh1c2VybmFtZ" ascii
      $sa3 = "Vc2VyLmZpbmRfYnkodXNlcm5hbW" ascii
      $sb1 = "dXNlci5hZG1pb" ascii
      $sb2 = "VzZXIuYWRtaW" ascii
      $sb3 = "1c2VyLmFkbWlu" ascii
      $sc1 = "dXNlci5zYXZlI" ascii
      $sc2 = "VzZXIuc2F2ZS" ascii
      $sc3 = "1c2VyLnNhdmUh" ascii
   condition: 
      1 of ( $sa* ) and 1 of ( $sb* ) and 1 of ( $sc* )
}