rule TTP_XOR_QUAD_CurrentVersionRun_b679 {
  strings:
    $key_b679 = { e5 16 [2] c1 18 [2] ea 34 [2] c4 16 [2] d0 0d [2] df 17 [2] c1 0a [2] c3 0b [2] d8 0d [2] c4 0a [2] d8 25 }

  condition:
    any of them
}