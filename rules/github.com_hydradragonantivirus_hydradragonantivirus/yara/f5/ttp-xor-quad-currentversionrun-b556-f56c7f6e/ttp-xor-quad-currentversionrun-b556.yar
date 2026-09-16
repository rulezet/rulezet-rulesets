rule TTP_XOR_QUAD_CurrentVersionRun_b556 {
  strings:
    $key_b556 = { e6 39 [2] c2 37 [2] e9 1b [2] c7 39 [2] d3 22 [2] dc 38 [2] c2 25 [2] c0 24 [2] db 22 [2] c7 25 [2] db 0a }

  condition:
    any of them
}