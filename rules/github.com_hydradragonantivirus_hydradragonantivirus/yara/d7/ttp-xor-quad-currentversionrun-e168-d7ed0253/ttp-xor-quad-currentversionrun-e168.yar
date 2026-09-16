rule TTP_XOR_QUAD_CurrentVersionRun_e168 {
  strings:
    $key_e168 = { b2 07 [2] 96 09 [2] bd 25 [2] 93 07 [2] 87 1c [2] 88 06 [2] 96 1b [2] 94 1a [2] 8f 1c [2] 93 1b [2] 8f 34 }

  condition:
    any of them
}