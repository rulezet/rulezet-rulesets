rule TTP_XOR_QUAD_CurrentVersionRun_b330 {
  strings:
    $key_b330 = { e0 5f [2] c4 51 [2] ef 7d [2] c1 5f [2] d5 44 [2] da 5e [2] c4 43 [2] c6 42 [2] dd 44 [2] c1 43 [2] dd 6c }

  condition:
    any of them
}