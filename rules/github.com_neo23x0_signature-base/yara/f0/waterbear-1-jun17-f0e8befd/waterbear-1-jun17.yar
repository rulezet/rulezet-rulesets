rule Waterbear_1_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "dd3676f478ee6f814077a12302d38426760b0701bb629f413f7bf2ec71319db5"
      id = "2202506a-6009-5321-a8b2-df3bff51d06f"
   strings:
      $s1 = "\\Release\\svc.pdb" ascii
      $s2 = "svc.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}