rule APT_PY_ESXi_Backdoor_Dec22_RID3009 : APT DEMO SCRIPT T1059_006 {
   meta:
      description = "Detects Python backdoor found on ESXi servers"
      author = "Florian Roth"
      reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
      date = "2022-12-14 12:22:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "cmd = str(base64.b64decode(encoded_cmd), " ascii
      $x2 = "sh -i 2>&1 | nc %s %s > /tmp/" ascii
   condition: 
      filesize < 10KB and 1 of them or all of them
}