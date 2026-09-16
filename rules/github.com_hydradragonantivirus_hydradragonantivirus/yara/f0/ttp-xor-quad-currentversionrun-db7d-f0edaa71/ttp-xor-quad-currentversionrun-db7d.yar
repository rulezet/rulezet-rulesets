rule TTP_XOR_QUAD_CurrentVersionRun_db7d {
  strings:
    $key_db7d = { 88 12 [2] ac 1c [2] 87 30 [2] a9 12 [2] bd 09 [2] b2 13 [2] ac 0e [2] ae 0f [2] b5 09 [2] a9 0e [2] b5 21 }

  condition:
    any of them
}