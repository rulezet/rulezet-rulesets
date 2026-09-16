rule TTP_XOR_QUAD_CurrentVersionRun_e105 {
  strings:
    $key_e105 = { b2 6a [2] 96 64 [2] bd 48 [2] 93 6a [2] 87 71 [2] 88 6b [2] 96 76 [2] 94 77 [2] 8f 71 [2] 93 76 [2] 8f 59 }

  condition:
    any of them
}