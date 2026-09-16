rule TTP_XOR_QUAD_CurrentVersionRun_b85d {
  strings:
    $key_b85d = { eb 32 [2] cf 3c [2] e4 10 [2] ca 32 [2] de 29 [2] d1 33 [2] cf 2e [2] cd 2f [2] d6 29 [2] ca 2e [2] d6 01 }

  condition:
    any of them
}