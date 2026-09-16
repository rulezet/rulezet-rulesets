rule TTP_XOR_QUAD_CurrentVersionRun_db7a {
  strings:
    $key_db7a = { 88 15 [2] ac 1b [2] 87 37 [2] a9 15 [2] bd 0e [2] b2 14 [2] ac 09 [2] ae 08 [2] b5 0e [2] a9 09 [2] b5 26 }

  condition:
    any of them
}