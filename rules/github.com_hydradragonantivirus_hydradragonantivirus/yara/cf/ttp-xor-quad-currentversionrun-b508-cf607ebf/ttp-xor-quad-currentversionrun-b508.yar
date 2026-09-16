rule TTP_XOR_QUAD_CurrentVersionRun_b508 {
  strings:
    $key_b508 = { e6 67 [2] c2 69 [2] e9 45 [2] c7 67 [2] d3 7c [2] dc 66 [2] c2 7b [2] c0 7a [2] db 7c [2] c7 7b [2] db 54 }

  condition:
    any of them
}