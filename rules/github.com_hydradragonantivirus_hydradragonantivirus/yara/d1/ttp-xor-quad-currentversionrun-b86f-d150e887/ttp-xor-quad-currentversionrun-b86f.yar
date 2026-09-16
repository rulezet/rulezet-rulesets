rule TTP_XOR_QUAD_CurrentVersionRun_b86f {
  strings:
    $key_b86f = { eb 00 [2] cf 0e [2] e4 22 [2] ca 00 [2] de 1b [2] d1 01 [2] cf 1c [2] cd 1d [2] d6 1b [2] ca 1c [2] d6 33 }

  condition:
    any of them
}