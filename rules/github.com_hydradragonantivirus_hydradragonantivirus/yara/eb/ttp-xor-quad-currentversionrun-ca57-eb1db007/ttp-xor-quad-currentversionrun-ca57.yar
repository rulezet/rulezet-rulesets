rule TTP_XOR_QUAD_CurrentVersionRun_ca57 {
  strings:
    $key_ca57 = { 99 38 [2] bd 36 [2] 96 1a [2] b8 38 [2] ac 23 [2] a3 39 [2] bd 24 [2] bf 25 [2] a4 23 [2] b8 24 [2] a4 0b }

  condition:
    any of them
}