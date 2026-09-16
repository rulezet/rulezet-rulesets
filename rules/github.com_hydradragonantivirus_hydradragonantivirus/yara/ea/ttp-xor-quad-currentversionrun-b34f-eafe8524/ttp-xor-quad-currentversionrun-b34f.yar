rule TTP_XOR_QUAD_CurrentVersionRun_b34f {
  strings:
    $key_b34f = { e0 20 [2] c4 2e [2] ef 02 [2] c1 20 [2] d5 3b [2] da 21 [2] c4 3c [2] c6 3d [2] dd 3b [2] c1 3c [2] dd 13 }

  condition:
    any of them
}