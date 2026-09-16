rule EquationGroup_Auditcleaner {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file Auditcleaner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8c172a60fa9e50f0df493bf5baeb7cc311baef327431526c47114335e0097626"
      id = "39ed798a-221d-5a4b-8809-db01d5241418"
   strings:
      $x1 = "> /var/log/audit/audit.log; rm -f ." ascii
      $x2 = "Pastables to run on target:" ascii
      $x3 = "cp /var/log/audit/audit.log .tmp" ascii

      $l1 = "Here is the first good cron session from" fullword ascii
      $l2 = "No need to clean LOGIN lines." fullword ascii
   condition:
      ( filesize < 300KB and 1 of them )
}