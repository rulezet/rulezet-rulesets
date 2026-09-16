rule TTP_XOR_QUAD_CurrentVersionRun_b501 {
  strings:
    $key_b501 = { e6 6e [2] c2 60 [2] e9 4c [2] c7 6e [2] d3 75 [2] dc 6f [2] c2 72 [2] c0 73 [2] db 75 [2] c7 72 [2] db 5d }

  condition:
    any of them
}