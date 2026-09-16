rule TTP_XOR_QUAD_CurrentVersionRun_b762 {
  strings:
    $key_b762 = { e4 0d [2] c0 03 [2] eb 2f [2] c5 0d [2] d1 16 [2] de 0c [2] c0 11 [2] c2 10 [2] d9 16 [2] c5 11 [2] d9 3e }

  condition:
    any of them
}