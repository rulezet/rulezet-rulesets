rule APT_APT29_NOBELIUM_BoomBox_May21_1_RID31ED : APT DEMO EXE FILE G0016 G0118 RUSSIA {
   meta:
      description = "Detects BoomBox malware as described in APT29 NOBELIUM report"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
      date = "2021-05-27 13:43:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-20"
      tags = "APT, DEMO, EXE, FILE, G0016, G0118, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "]::FromBase64String($" ascii wide
      $xa1 = "123do3y4r378o5t34onf7t3o573tfo73" ascii wide fullword
      $xa2 = "1233t04p7jn3n4rg" ascii wide fullword
      $s1 = "\\Release\\BOOM.pdb" ascii
      $s2 = "/files/upload" ascii
      $s3 = "/tmp/readme.pdf" ascii fullword
      $s4 = "/new/{0}" ascii fullword
      $s5 = "(&(objectClass=user)(objectCategory=person))" 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d or 1 of ( $a* ) ) and ( 1 of ( $x* ) or 3 of ( $s* ) )
}