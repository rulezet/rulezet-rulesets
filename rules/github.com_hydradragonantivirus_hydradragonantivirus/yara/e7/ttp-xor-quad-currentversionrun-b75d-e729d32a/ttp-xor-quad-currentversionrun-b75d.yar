rule TTP_XOR_QUAD_CurrentVersionRun_b75d {
  strings:
    $key_b75d = { e4 32 [2] c0 3c [2] eb 10 [2] c5 32 [2] d1 29 [2] de 33 [2] c0 2e [2] c2 2f [2] d9 29 [2] c5 2e [2] d9 01 }

  condition:
    any of them
}