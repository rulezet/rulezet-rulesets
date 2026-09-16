rule TTP_XOR_QUAD_CurrentVersionRun_b842 {
  strings:
    $key_b842 = { eb 2d [2] cf 23 [2] e4 0f [2] ca 2d [2] de 36 [2] d1 2c [2] cf 31 [2] cd 30 [2] d6 36 [2] ca 31 [2] d6 1e }

  condition:
    any of them
}