rule TTP_XOR_QUAD_CurrentVersionRun_e104 {
  strings:
    $key_e104 = { b2 6b [2] 96 65 [2] bd 49 [2] 93 6b [2] 87 70 [2] 88 6a [2] 96 77 [2] 94 76 [2] 8f 70 [2] 93 77 [2] 8f 58 }

  condition:
    any of them
}