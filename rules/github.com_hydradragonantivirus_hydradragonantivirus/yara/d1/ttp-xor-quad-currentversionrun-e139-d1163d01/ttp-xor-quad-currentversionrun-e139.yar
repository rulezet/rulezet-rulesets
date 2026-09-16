rule TTP_XOR_QUAD_CurrentVersionRun_e139 {
  strings:
    $key_e139 = { b2 56 [2] 96 58 [2] bd 74 [2] 93 56 [2] 87 4d [2] 88 57 [2] 96 4a [2] 94 4b [2] 8f 4d [2] 93 4a [2] 8f 65 }

  condition:
    any of them
}