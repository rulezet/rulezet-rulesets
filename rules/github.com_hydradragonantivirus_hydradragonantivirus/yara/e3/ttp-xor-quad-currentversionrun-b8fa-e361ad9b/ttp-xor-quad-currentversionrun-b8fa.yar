rule TTP_XOR_QUAD_CurrentVersionRun_b8fa {
  strings:
    $key_b8fa = { eb 95 [2] cf 9b [2] e4 b7 [2] ca 95 [2] de 8e [2] d1 94 [2] cf 89 [2] cd 88 [2] d6 8e [2] ca 89 [2] d6 a6 }

  condition:
    any of them
}