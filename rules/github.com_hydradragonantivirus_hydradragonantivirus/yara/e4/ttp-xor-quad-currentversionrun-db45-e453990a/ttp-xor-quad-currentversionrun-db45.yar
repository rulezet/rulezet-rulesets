rule TTP_XOR_QUAD_CurrentVersionRun_db45 {
  strings:
    $key_db45 = { 88 2a [2] ac 24 [2] 87 08 [2] a9 2a [2] bd 31 [2] b2 2b [2] ac 36 [2] ae 37 [2] b5 31 [2] a9 36 [2] b5 19 }

  condition:
    any of them
}