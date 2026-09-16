rule TTP_XOR_QUAD_CurrentVersionRun_b544 {
  strings:
    $key_b544 = { e6 2b [2] c2 25 [2] e9 09 [2] c7 2b [2] d3 30 [2] dc 2a [2] c2 37 [2] c0 36 [2] db 30 [2] c7 37 [2] db 18 }

  condition:
    any of them
}