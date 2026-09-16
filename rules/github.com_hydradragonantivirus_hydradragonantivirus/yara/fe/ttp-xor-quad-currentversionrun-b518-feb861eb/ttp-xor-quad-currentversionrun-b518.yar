rule TTP_XOR_QUAD_CurrentVersionRun_b518 {
  strings:
    $key_b518 = { e6 77 [2] c2 79 [2] e9 55 [2] c7 77 [2] d3 6c [2] dc 76 [2] c2 6b [2] c0 6a [2] db 6c [2] c7 6b [2] db 44 }

  condition:
    any of them
}