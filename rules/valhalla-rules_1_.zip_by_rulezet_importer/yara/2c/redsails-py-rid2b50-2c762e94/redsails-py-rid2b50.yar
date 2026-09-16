rule redSails_PY_RID2B50 : DEMO HKTL SCRIPT T1059_006 {
   meta:
      description = "Detects Red Sails Hacktool - Python"
      author = "Florian Roth"
      reference = "https://github.com/BeetleChunks/redsails"
      date = "2017-10-02 09:01:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6ebedff41992b9536fe9b1b704a29c8c1d1550b00e14055e3c6376f75e462661"
      hash2 = "5ec20cb99030f48ba512cbc7998b943bebe49396b20cf578c26debbf14176e5e"
      tags = "DEMO, HKTL, SCRIPT, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Gained command shell on host" fullword ascii
      $x2 = "[!] Received an ERROR in shell()" fullword ascii
      $x3 = "Target IP address with backdoor installed" fullword ascii
      $x4 = "Open backdoor port on target machine" fullword ascii
      $x5 = "Backdoor port to open on victim machine" fullword ascii
   condition: 
      1 of them
}