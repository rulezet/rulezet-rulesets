rule custom_ssh_backdoor_server_RID31F3 : DEMO HKTL SCRIPT T1021_004 T1059_006 {
   meta:
      description = "Custome SSH backdoor based on python and paramiko - file server.py"
      author = "Florian Roth"
      reference = "https://github.com/joridos/custom-ssh-backdoor"
      date = "2015-05-14 13:44:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, HKTL, SCRIPT, T1021_004, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "command= raw_input(\"Enter command: \").strip('n')" fullword ascii
      $s1 = "print '[-] (Failed to load moduli -- gex will be unsupported.)'" fullword ascii
      $s2 = "print '[-] Listen/bind/accept failed: ' + str(e)" fullword ascii
   condition: 
      2 of them
}