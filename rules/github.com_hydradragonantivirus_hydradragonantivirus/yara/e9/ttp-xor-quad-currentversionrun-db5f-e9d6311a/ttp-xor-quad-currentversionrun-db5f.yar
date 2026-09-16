rule TTP_XOR_QUAD_CurrentVersionRun_db5f {
  strings:
    $key_db5f = { 88 30 [2] ac 3e [2] 87 12 [2] a9 30 [2] bd 2b [2] b2 31 [2] ac 2c [2] ae 2d [2] b5 2b [2] a9 2c [2] b5 03 }

  condition:
    any of them
}