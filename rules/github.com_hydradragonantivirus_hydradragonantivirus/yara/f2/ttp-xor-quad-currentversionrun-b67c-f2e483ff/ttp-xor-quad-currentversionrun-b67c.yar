rule TTP_XOR_QUAD_CurrentVersionRun_b67c {
  strings:
    $key_b67c = { e5 13 [2] c1 1d [2] ea 31 [2] c4 13 [2] d0 08 [2] df 12 [2] c1 0f [2] c3 0e [2] d8 08 [2] c4 0f [2] d8 20 }

  condition:
    any of them
}