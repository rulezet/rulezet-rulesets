rule TTP_XOR_QUAD_CurrentVersionRun_b109 {
  strings:
    $key_b109 = { e2 66 [2] c6 68 [2] ed 44 [2] c3 66 [2] d7 7d [2] d8 67 [2] c6 7a [2] c4 7b [2] df 7d [2] c3 7a [2] df 55 }

  condition:
    any of them
}