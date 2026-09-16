rule EquationGroup_Auditcleaner_RID3194 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file Auditcleaner"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8c172a60fa9e50f0df493bf5baeb7cc311baef327431526c47114335e0097626"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "> /var/log/audit/audit.log; rm -f ." ascii
      $x2 = "Pastables to run on target:" ascii
      $x3 = "cp /var/log/audit/audit.log .tmp" ascii
      $l1 = "Here is the first good cron session from" fullword ascii
      $l2 = "No need to clean LOGIN lines." fullword ascii
   condition: 
      ( filesize < 300KB and 1 of them )
}