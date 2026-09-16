rule Binary_Drop_Certutil_RID2F15 : DEMO SUSP T1132_001 T1140 {
   meta:
      description = "Drop binary as base64 encoded cert trick"
      author = "Florian Roth"
      reference = "https://gist.github.com/mattifestation/47f9e8a431f96a266522"
      date = "2015-07-15 11:42:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, SUSP, T1132_001, T1140"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo -----BEGIN CERTIFICATE----- >" ascii
      $s1 = "echo -----END CERTIFICATE----- >>" ascii
      $s2 = "certutil -decode " ascii
   condition: 
      filesize < 10KB and all of them
}