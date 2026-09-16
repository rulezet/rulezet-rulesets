rule TTP_XOR_QUAD_CurrentVersionRun_b53b {
  strings:
    $key_b53b = { e6 54 [2] c2 5a [2] e9 76 [2] c7 54 [2] d3 4f [2] dc 55 [2] c2 48 [2] c0 49 [2] db 4f [2] c7 48 [2] db 67 }

  condition:
    any of them
}