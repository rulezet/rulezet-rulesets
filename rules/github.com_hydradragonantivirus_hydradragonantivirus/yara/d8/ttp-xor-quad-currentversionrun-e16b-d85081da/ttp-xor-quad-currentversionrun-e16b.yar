rule TTP_XOR_QUAD_CurrentVersionRun_e16b {
  strings:
    $key_e16b = { b2 04 [2] 96 0a [2] bd 26 [2] 93 04 [2] 87 1f [2] 88 05 [2] 96 18 [2] 94 19 [2] 8f 1f [2] 93 18 [2] 8f 37 }

  condition:
    any of them
}