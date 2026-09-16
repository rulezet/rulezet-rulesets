rule TTP_XOR_QUAD_CurrentVersionRun_b809 {
  strings:
    $key_b809 = { eb 66 [2] cf 68 [2] e4 44 [2] ca 66 [2] de 7d [2] d1 67 [2] cf 7a [2] cd 7b [2] d6 7d [2] ca 7a [2] d6 55 }

  condition:
    any of them
}