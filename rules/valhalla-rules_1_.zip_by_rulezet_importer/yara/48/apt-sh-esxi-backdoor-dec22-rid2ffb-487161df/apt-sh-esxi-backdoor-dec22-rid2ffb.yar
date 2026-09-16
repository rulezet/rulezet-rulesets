rule APT_SH_ESXi_Backdoor_Dec22_RID2FFB : APT DEMO SCRIPT {
   meta:
      description = "Detects malicious script found on ESXi servers"
      author = "Florian Roth"
      reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
      date = "2022-12-14 12:20:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "mv /bin/hostd-probe.sh /bin/hostd-probe.sh.1" ascii fullword
      $x2 = "/bin/nohup /bin/python -u /store/packages/vmtools.py" ascii
      $x3 = "/bin/rm /bin/hostd-probe.sh.1" 
   condition: 
      filesize < 10KB and 1 of them
}