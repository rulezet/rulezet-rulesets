rule TTP_XOR_QUAD_CurrentVersionRun_b6e9 {
  strings:
    $key_b6e9 = { e5 86 [2] c1 88 [2] ea a4 [2] c4 86 [2] d0 9d [2] df 87 [2] c1 9a [2] c3 9b [2] d8 9d [2] c4 9a [2] d8 b5 }

  condition:
    any of them
}