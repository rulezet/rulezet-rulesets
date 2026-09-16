rule TTP_XOR_QUAD_CurrentVersionRun_b516 {
  strings:
    $key_b516 = { e6 79 [2] c2 77 [2] e9 5b [2] c7 79 [2] d3 62 [2] dc 78 [2] c2 65 [2] c0 64 [2] db 62 [2] c7 65 [2] db 4a }

  condition:
    any of them
}