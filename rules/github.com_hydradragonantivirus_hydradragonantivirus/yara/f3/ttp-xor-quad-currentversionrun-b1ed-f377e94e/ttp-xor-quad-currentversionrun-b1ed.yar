rule TTP_XOR_QUAD_CurrentVersionRun_b1ed {
  strings:
    $key_b1ed = { e2 82 [2] c6 8c [2] ed a0 [2] c3 82 [2] d7 99 [2] d8 83 [2] c6 9e [2] c4 9f [2] df 99 [2] c3 9e [2] df b1 }

  condition:
    any of them
}