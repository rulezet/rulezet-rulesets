rule TTP_XOR_QUAD_CurrentVersionRun_db6e {
  strings:
    $key_db6e = { 88 01 [2] ac 0f [2] 87 23 [2] a9 01 [2] bd 1a [2] b2 00 [2] ac 1d [2] ae 1c [2] b5 1a [2] a9 1d [2] b5 32 }

  condition:
    any of them
}