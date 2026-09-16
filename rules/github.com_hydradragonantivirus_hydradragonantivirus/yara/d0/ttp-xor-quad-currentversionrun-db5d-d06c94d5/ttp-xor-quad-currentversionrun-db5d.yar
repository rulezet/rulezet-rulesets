rule TTP_XOR_QUAD_CurrentVersionRun_db5d {
  strings:
    $key_db5d = { 88 32 [2] ac 3c [2] 87 10 [2] a9 32 [2] bd 29 [2] b2 33 [2] ac 2e [2] ae 2f [2] b5 29 [2] a9 2e [2] b5 01 }

  condition:
    any of them
}