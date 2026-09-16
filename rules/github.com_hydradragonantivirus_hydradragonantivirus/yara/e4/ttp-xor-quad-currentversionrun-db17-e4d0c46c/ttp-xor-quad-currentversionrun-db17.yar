rule TTP_XOR_QUAD_CurrentVersionRun_db17 {
  strings:
    $key_db17 = { 88 78 [2] ac 76 [2] 87 5a [2] a9 78 [2] bd 63 [2] b2 79 [2] ac 64 [2] ae 65 [2] b5 63 [2] a9 64 [2] b5 4b }

  condition:
    any of them
}