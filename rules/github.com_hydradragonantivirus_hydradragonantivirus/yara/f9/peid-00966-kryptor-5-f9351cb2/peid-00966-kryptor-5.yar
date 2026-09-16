rule PEiD_00966_kryptor_5_ {
  meta:
    description = "[kryptor 5]"
    ep_only     = "true"

  strings:
    $a = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }

  condition:
    $a
}