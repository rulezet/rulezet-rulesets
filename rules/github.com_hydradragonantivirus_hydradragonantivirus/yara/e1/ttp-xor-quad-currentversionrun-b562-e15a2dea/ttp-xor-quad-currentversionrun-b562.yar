rule TTP_XOR_QUAD_CurrentVersionRun_b562 {
  strings:
    $key_b562 = { e6 0d [2] c2 03 [2] e9 2f [2] c7 0d [2] d3 16 [2] dc 0c [2] c2 11 [2] c0 10 [2] db 16 [2] c7 11 [2] db 3e }

  condition:
    any of them
}