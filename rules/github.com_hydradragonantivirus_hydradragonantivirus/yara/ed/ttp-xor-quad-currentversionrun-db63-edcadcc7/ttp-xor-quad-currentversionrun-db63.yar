rule TTP_XOR_QUAD_CurrentVersionRun_db63 {
  strings:
    $key_db63 = { 88 0c [2] ac 02 [2] 87 2e [2] a9 0c [2] bd 17 [2] b2 0d [2] ac 10 [2] ae 11 [2] b5 17 [2] a9 10 [2] b5 3f }

  condition:
    any of them
}