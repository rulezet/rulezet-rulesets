rule TTP_XOR_QUAD_CurrentVersionRun_b825 {
  strings:
    $key_b825 = { eb 4a [2] cf 44 [2] e4 68 [2] ca 4a [2] de 51 [2] d1 4b [2] cf 56 [2] cd 57 [2] d6 51 [2] ca 56 [2] d6 79 }

  condition:
    any of them
}