rule PEiD_01929_RCryptor_v1_6____Vaska_ {
  meta:
    description = "[RCryptor v1.6 -> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 33 D0 68 ?? ?? ?? ?? FF D2 }

  condition:
    $a
}