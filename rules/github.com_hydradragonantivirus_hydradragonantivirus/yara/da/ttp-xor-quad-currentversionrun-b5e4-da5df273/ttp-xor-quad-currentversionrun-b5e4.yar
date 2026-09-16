rule TTP_XOR_QUAD_CurrentVersionRun_b5e4 {
  strings:
    $key_b5e4 = { e6 8b [2] c2 85 [2] e9 a9 [2] c7 8b [2] d3 90 [2] dc 8a [2] c2 97 [2] c0 96 [2] db 90 [2] c7 97 [2] db b8 }

  condition:
    any of them
}