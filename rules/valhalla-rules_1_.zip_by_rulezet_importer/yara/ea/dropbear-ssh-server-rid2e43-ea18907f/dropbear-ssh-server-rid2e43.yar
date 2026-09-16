rule DropBear_SSH_Server_RID2E43 : APT DEMO EXE FILE T1021_004 {
   meta:
      description = "Detects DropBear SSH Server (not a threat but used to maintain access)"
      author = "Florian Roth"
      reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
      date = "2016-01-03 11:07:01"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, T1021_004"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
      $s2 = "Badly formatted command= authorized_keys option" fullword ascii
      $s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
      $s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
      $s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them
}