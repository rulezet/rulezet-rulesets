rule TTP_XOR_QUAD_CurrentVersionRun_b826 {
  strings:
    $key_b826 = { eb 49 [2] cf 47 [2] e4 6b [2] ca 49 [2] de 52 [2] d1 48 [2] cf 55 [2] cd 54 [2] d6 52 [2] ca 55 [2] d6 7a }

  condition:
    any of them
}