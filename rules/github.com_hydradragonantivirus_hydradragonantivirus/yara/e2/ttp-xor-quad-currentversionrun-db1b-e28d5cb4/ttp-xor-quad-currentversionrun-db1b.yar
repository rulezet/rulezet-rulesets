rule TTP_XOR_QUAD_CurrentVersionRun_db1b {
  strings:
    $key_db1b = { 88 74 [2] ac 7a [2] 87 56 [2] a9 74 [2] bd 6f [2] b2 75 [2] ac 68 [2] ae 69 [2] b5 6f [2] a9 68 [2] b5 47 }

  condition:
    any of them
}