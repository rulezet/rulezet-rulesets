rule TTP_XOR_QUAD_CurrentVersionRun_b633 {
  strings:
    $key_b633 = { e5 5c [2] c1 52 [2] ea 7e [2] c4 5c [2] d0 47 [2] df 5d [2] c1 40 [2] c3 41 [2] d8 47 [2] c4 40 [2] d8 6f }

  condition:
    any of them
}