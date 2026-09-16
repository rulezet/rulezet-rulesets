rule TTP_XOR_QUAD_CurrentVersionRun_b5eb {
  strings:
    $key_b5eb = { e6 84 [2] c2 8a [2] e9 a6 [2] c7 84 [2] d3 9f [2] dc 85 [2] c2 98 [2] c0 99 [2] db 9f [2] c7 98 [2] db b7 }

  condition:
    any of them
}