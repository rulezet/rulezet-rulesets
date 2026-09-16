rule TTP_XOR_QUAD_CurrentVersionRun_b572 {
  strings:
    $key_b572 = { e6 1d [2] c2 13 [2] e9 3f [2] c7 1d [2] d3 06 [2] dc 1c [2] c2 01 [2] c0 00 [2] db 06 [2] c7 01 [2] db 2e }

  condition:
    any of them
}