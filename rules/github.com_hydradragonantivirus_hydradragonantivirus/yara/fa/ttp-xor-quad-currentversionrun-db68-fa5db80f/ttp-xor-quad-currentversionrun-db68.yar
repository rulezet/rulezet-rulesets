rule TTP_XOR_QUAD_CurrentVersionRun_db68 {
  strings:
    $key_db68 = { 88 07 [2] ac 09 [2] 87 25 [2] a9 07 [2] bd 1c [2] b2 06 [2] ac 1b [2] ae 1a [2] b5 1c [2] a9 1b [2] b5 34 }

  condition:
    any of them
}