rule TTP_XOR_QUAD_CurrentVersionRun_b836 {
  strings:
    $key_b836 = { eb 59 [2] cf 57 [2] e4 7b [2] ca 59 [2] de 42 [2] d1 58 [2] cf 45 [2] cd 44 [2] d6 42 [2] ca 45 [2] d6 6a }

  condition:
    any of them
}