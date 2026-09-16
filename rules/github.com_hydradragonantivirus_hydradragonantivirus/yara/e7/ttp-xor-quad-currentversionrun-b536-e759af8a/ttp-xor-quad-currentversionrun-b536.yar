rule TTP_XOR_QUAD_CurrentVersionRun_b536 {
  strings:
    $key_b536 = { e6 59 [2] c2 57 [2] e9 7b [2] c7 59 [2] d3 42 [2] dc 58 [2] c2 45 [2] c0 44 [2] db 42 [2] c7 45 [2] db 6a }

  condition:
    any of them
}