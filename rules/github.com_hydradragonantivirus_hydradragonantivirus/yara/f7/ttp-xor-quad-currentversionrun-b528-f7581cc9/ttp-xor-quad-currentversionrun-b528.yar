rule TTP_XOR_QUAD_CurrentVersionRun_b528 {
  strings:
    $key_b528 = { e6 47 [2] c2 49 [2] e9 65 [2] c7 47 [2] d3 5c [2] dc 46 [2] c2 5b [2] c0 5a [2] db 5c [2] c7 5b [2] db 74 }

  condition:
    any of them
}