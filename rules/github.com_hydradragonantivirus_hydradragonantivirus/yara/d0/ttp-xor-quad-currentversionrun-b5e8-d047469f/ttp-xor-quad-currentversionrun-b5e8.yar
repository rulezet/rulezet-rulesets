rule TTP_XOR_QUAD_CurrentVersionRun_b5e8 {
  strings:
    $key_b5e8 = { e6 87 [2] c2 89 [2] e9 a5 [2] c7 87 [2] d3 9c [2] dc 86 [2] c2 9b [2] c0 9a [2] db 9c [2] c7 9b [2] db b4 }

  condition:
    any of them
}