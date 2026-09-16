rule TTP_XOR_QUAD_CurrentVersionRun_a608 {
  strings:
    $key_a608 = { f5 67 [2] d1 69 [2] fa 45 [2] d4 67 [2] c0 7c [2] cf 66 [2] d1 7b [2] d3 7a [2] c8 7c [2] d4 7b [2] c8 54 }

  condition:
    any of them
}