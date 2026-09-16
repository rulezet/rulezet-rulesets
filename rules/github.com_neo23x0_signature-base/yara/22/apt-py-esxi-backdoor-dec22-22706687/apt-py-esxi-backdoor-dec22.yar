rule APT_PY_ESXi_Backdoor_Dec22 {
   meta:
      description = "Detects Python backdoor found on ESXi servers"
      author = "Florian Roth"
      reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
      date = "2022-12-14"
      score = 85
      id = "f0a3b9b9-0031-5d9f-97f8-70f83863ee63"
    strings:
      $x1 = "cmd = str(base64.b64decode(encoded_cmd), " ascii
      $x2 = "sh -i 2>&1 | nc %s %s > /tmp/" ascii
    condition:
      filesize < 10KB and 1 of them or all of them
}