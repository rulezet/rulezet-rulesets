rule TTP_XOR_QUAD_CurrentVersionRun_b85a {
  strings:
    $key_b85a = { eb 35 [2] cf 3b [2] e4 17 [2] ca 35 [2] de 2e [2] d1 34 [2] cf 29 [2] cd 28 [2] d6 2e [2] ca 29 [2] d6 06 }

  condition:
    any of them
}