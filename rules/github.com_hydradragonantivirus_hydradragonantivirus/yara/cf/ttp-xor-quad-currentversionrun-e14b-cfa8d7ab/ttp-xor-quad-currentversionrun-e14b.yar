rule TTP_XOR_QUAD_CurrentVersionRun_e14b {
  strings:
    $key_e14b = { b2 24 [2] 96 2a [2] bd 06 [2] 93 24 [2] 87 3f [2] 88 25 [2] 96 38 [2] 94 39 [2] 8f 3f [2] 93 38 [2] 8f 17 }

  condition:
    any of them
}