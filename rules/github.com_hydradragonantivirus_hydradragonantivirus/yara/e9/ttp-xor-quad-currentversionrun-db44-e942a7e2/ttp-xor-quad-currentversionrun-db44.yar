rule TTP_XOR_QUAD_CurrentVersionRun_db44 {
  strings:
    $key_db44 = { 88 2b [2] ac 25 [2] 87 09 [2] a9 2b [2] bd 30 [2] b2 2a [2] ac 37 [2] ae 36 [2] b5 30 [2] a9 37 [2] b5 18 }

  condition:
    any of them
}