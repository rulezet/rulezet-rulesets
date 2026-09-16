rule OpCloudHopper_Cloaked_PSCP {
   meta:
      description = "Tool used in Operation Cloud Hopper - pscp.exe cloaked as rundll32.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      score = 90
      id = "c1e2e456-dbdd-54cf-b0e0-b356f291cfcd"
   strings:
      $s1 = "AES-256 SDCTR" ascii
      $s2 = "direct-tcpip" ascii
   condition:
      all of them and filename == "rundll32.exe"
}