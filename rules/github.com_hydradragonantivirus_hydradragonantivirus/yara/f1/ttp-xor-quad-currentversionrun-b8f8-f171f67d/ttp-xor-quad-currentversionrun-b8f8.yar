rule TTP_XOR_QUAD_CurrentVersionRun_b8f8 {
  strings:
    $key_b8f8 = { eb 97 [2] cf 99 [2] e4 b5 [2] ca 97 [2] de 8c [2] d1 96 [2] cf 8b [2] cd 8a [2] d6 8c [2] ca 8b [2] d6 a4 }

  condition:
    any of them
}