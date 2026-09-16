rule EquationGroup_tmpwatch_RID302B : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 12:28:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "65ed8066a3a240ee2e7556da74933a9b25c5109ffad893c21a626ea1b686d7c1"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "chown root:root /tmp/.scsi/dev/bin/gsh" fullword ascii
      $s2 = "chmod 4777 /tmp/.scsi/dev/bin/gsh" fullword ascii
   condition: 
      ( filesize < 1KB and 1 of them )
}