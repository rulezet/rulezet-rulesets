rule TTP_XOR_QUAD_CurrentVersionRun_b341 {
  strings:
    $key_b341 = { e0 2e [2] c4 20 [2] ef 0c [2] c1 2e [2] d5 35 [2] da 2f [2] c4 32 [2] c6 33 [2] dd 35 [2] c1 32 [2] dd 1d }

  condition:
    any of them
}