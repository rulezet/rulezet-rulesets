rule TTP_XOR_QUAD_CurrentVersionRun_b8f4 {
  strings:
    $key_b8f4 = { eb 9b [2] cf 95 [2] e4 b9 [2] ca 9b [2] de 80 [2] d1 9a [2] cf 87 [2] cd 86 [2] d6 80 [2] ca 87 [2] d6 a8 }

  condition:
    any of them
}