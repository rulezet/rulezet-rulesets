rule vault8_hived_unpatched {
  meta:
    description = "Vault 8 Hive hived sever implant unpatched"

  strings:
        $h0 = { 7A D8 CF B6 }     $h1 = { B6 CF D8 7A } 
  condition:
    ($h0 or $h1) and vault8_hived
}