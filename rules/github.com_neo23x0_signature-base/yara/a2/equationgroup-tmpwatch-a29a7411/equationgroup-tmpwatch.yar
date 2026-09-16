rule EquationGroup_tmpwatch {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "65ed8066a3a240ee2e7556da74933a9b25c5109ffad893c21a626ea1b686d7c1"
      id = "2c8cac7a-761f-59f4-bc04-285af4dbe184"
   strings:
      $s1 = "chown root:root /tmp/.scsi/dev/bin/gsh" fullword ascii
      $s2 = "chmod 4777 /tmp/.scsi/dev/bin/gsh" fullword ascii
   condition:
      ( filesize < 1KB and 1 of them )
}