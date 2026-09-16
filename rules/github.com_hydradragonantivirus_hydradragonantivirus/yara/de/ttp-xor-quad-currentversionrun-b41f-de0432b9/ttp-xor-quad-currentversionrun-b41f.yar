rule TTP_XOR_QUAD_CurrentVersionRun_b41f {
  strings:
    $key_b41f = { e7 70 [2] c3 7e [2] e8 52 [2] c6 70 [2] d2 6b [2] dd 71 [2] c3 6c [2] c1 6d [2] da 6b [2] c6 6c [2] da 43 }

  condition:
    any of them
}