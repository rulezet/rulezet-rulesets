rule TTP_XOR_QUAD_CurrentVersionRun_dbf5 {
  strings:
    $key_dbf5 = { 88 9a [2] ac 94 [2] 87 b8 [2] a9 9a [2] bd 81 [2] b2 9b [2] ac 86 [2] ae 87 [2] b5 81 [2] a9 86 [2] b5 a9 }

  condition:
    any of them
}