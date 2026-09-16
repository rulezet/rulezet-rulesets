rule TTP_XOR_QUAD_CurrentVersionRun_b162 {
  strings:
    $key_b162 = { e2 0d [2] c6 03 [2] ed 2f [2] c3 0d [2] d7 16 [2] d8 0c [2] c6 11 [2] c4 10 [2] df 16 [2] c3 11 [2] df 3e }

  condition:
    any of them
}