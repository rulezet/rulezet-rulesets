rule TTP_XOR_QUAD_CurrentVersionRun_b8ef {
  strings:
    $key_b8ef = { eb 80 [2] cf 8e [2] e4 a2 [2] ca 80 [2] de 9b [2] d1 81 [2] cf 9c [2] cd 9d [2] d6 9b [2] ca 9c [2] d6 b3 }

  condition:
    any of them
}