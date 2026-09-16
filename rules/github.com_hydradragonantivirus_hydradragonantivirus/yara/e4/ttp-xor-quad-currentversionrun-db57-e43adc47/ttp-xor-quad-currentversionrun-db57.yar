rule TTP_XOR_QUAD_CurrentVersionRun_db57 {
  strings:
    $key_db57 = { 88 38 [2] ac 36 [2] 87 1a [2] a9 38 [2] bd 23 [2] b2 39 [2] ac 24 [2] ae 25 [2] b5 23 [2] a9 24 [2] b5 0b }

  condition:
    any of them
}