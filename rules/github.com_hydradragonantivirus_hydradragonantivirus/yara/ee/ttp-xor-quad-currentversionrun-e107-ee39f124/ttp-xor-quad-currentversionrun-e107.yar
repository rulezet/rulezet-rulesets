rule TTP_XOR_QUAD_CurrentVersionRun_e107 {
  strings:
    $key_e107 = { b2 68 [2] 96 66 [2] bd 4a [2] 93 68 [2] 87 73 [2] 88 69 [2] 96 74 [2] 94 75 [2] 8f 73 [2] 93 74 [2] 8f 5b }

  condition:
    any of them
}