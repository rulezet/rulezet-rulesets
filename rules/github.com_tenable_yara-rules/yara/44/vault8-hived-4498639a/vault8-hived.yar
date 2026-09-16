rule vault8_hived {
  meta:
    description = "Vault 8 Hive hived server implant"

  strings:
        $b0 = "Option K" fullword     $b1 = "./server.crt" fullword     $b2 = "./ca.crt" fullword     $b3 = "./server.key" fullword     $b4 = ".seedfile" fullword 
        $s0 = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" fullword     $s1 = {b6 bb df 8b 90 90 df 8c 97 90 8d 8b FF} 
  condition:
    (all of ($b*)) and (all of ($s*))
}