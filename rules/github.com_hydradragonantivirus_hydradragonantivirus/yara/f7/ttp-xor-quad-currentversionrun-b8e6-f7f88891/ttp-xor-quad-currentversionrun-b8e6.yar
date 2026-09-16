rule TTP_XOR_QUAD_CurrentVersionRun_b8e6 {
  strings:
    $key_b8e6 = { eb 89 [2] cf 87 [2] e4 ab [2] ca 89 [2] de 92 [2] d1 88 [2] cf 95 [2] cd 94 [2] d6 92 [2] ca 95 [2] d6 ba }

  condition:
    any of them
}