rule TTP_XOR_QUAD_CurrentVersionRun_b30f {
  strings:
    $key_b30f = { e0 60 [2] c4 6e [2] ef 42 [2] c1 60 [2] d5 7b [2] da 61 [2] c4 7c [2] c6 7d [2] dd 7b [2] c1 7c [2] dd 53 }

  condition:
    any of them
}