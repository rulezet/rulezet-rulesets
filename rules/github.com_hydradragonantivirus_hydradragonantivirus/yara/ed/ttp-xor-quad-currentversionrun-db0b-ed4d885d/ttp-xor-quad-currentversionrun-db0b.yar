rule TTP_XOR_QUAD_CurrentVersionRun_db0b {
  strings:
    $key_db0b = { 88 64 [2] ac 6a [2] 87 46 [2] a9 64 [2] bd 7f [2] b2 65 [2] ac 78 [2] ae 79 [2] b5 7f [2] a9 78 [2] b5 57 }

  condition:
    any of them
}