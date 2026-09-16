rule APT_EQGRP_eligiblecandidate_RID310D : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file eligiblecandidate.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 13:06:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c4567c00734dedf1c875ecbbd56c1561a1610bedb4621d9c8899acec57353d86"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $o1 = "Connection timed out. Only a problem if the callback was not received." fullword ascii
      $o2 = "Could not reliably detect cookie. Using 'session_id'..." fullword ascii
      $c1 = "def build_exploit_payload(self,cmd=\"/tmp/httpd\"):" fullword ascii
      $c2 = "self.build_exploit_payload(cmd)" fullword ascii
   condition: 
      1 of them
}