rule APT_Cloaked_CERTUTIL {
   meta:
      description = "Detects a renamed certutil.exe utility that is often used to decode encoded payloads"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-14"
      modified = "2022-06-27"
      id = "13943cda-6bb1-5c6c-8e55-e8d4bba1ffef"
   strings:
      $s1 = "-------- CERT_CHAIN_CONTEXT --------" fullword ascii
      $s5 = "certutil.pdb" fullword ascii
      $s3 = "Password Token" fullword ascii
   condition:
      uint16(0) == 0x5a4d and all of them
      and not filename contains "certutil"
      and not filename contains "CertUtil"
      and not filename contains "Certutil"
      and not filepath contains "\\Bromium\\"
}