rule TTP_XOR_QUAD_CurrentVersionRun_b848 {
  strings:
    $key_b848 = { eb 27 [2] cf 29 [2] e4 05 [2] ca 27 [2] de 3c [2] d1 26 [2] cf 3b [2] cd 3a [2] d6 3c [2] ca 3b [2] d6 14 }

  condition:
    any of them
}