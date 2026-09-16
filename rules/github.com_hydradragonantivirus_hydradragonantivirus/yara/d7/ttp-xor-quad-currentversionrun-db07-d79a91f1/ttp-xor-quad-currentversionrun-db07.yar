rule TTP_XOR_QUAD_CurrentVersionRun_db07 {
  strings:
    $key_db07 = { 88 68 [2] ac 66 [2] 87 4a [2] a9 68 [2] bd 73 [2] b2 69 [2] ac 74 [2] ae 75 [2] b5 73 [2] a9 74 [2] b5 5b }

  condition:
    any of them
}