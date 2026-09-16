rule TTP_XOR_QUAD_CurrentVersionRun_db69 {
  strings:
    $key_db69 = { 88 06 [2] ac 08 [2] 87 24 [2] a9 06 [2] bd 1d [2] b2 07 [2] ac 1a [2] ae 1b [2] b5 1d [2] a9 1a [2] b5 35 }

  condition:
    any of them
}