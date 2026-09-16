rule TTP_XOR_QUAD_CurrentVersionRun_b603 {
  strings:
    $key_b603 = { e5 6c [2] c1 62 [2] ea 4e [2] c4 6c [2] d0 77 [2] df 6d [2] c1 70 [2] c3 71 [2] d8 77 [2] c4 70 [2] d8 5f }

  condition:
    any of them
}