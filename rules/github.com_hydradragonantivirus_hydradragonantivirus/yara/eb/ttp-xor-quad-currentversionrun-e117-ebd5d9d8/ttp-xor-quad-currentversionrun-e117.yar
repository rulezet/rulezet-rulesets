rule TTP_XOR_QUAD_CurrentVersionRun_e117 {
  strings:
    $key_e117 = { b2 78 [2] 96 76 [2] bd 5a [2] 93 78 [2] 87 63 [2] 88 79 [2] 96 64 [2] 94 65 [2] 8f 63 [2] 93 64 [2] 8f 4b }

  condition:
    any of them
}