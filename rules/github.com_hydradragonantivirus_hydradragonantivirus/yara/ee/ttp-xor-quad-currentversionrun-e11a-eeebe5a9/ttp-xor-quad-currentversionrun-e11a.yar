rule TTP_XOR_QUAD_CurrentVersionRun_e11a {
  strings:
    $key_e11a = { b2 75 [2] 96 7b [2] bd 57 [2] 93 75 [2] 87 6e [2] 88 74 [2] 96 69 [2] 94 68 [2] 8f 6e [2] 93 69 [2] 8f 46 }

  condition:
    any of them
}