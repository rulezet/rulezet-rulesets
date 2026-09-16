rule TTP_XOR_QUAD_CurrentVersionRun_b815 {
  strings:
    $key_b815 = { eb 7a [2] cf 74 [2] e4 58 [2] ca 7a [2] de 61 [2] d1 7b [2] cf 66 [2] cd 67 [2] d6 61 [2] ca 66 [2] d6 49 }

  condition:
    any of them
}