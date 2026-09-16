rule TTP_XOR_QUAD_CurrentVersionRun_db2c {
  strings:
    $key_db2c = { 88 43 [2] ac 4d [2] 87 61 [2] a9 43 [2] bd 58 [2] b2 42 [2] ac 5f [2] ae 5e [2] b5 58 [2] a9 5f [2] b5 70 }

  condition:
    any of them
}