rule TTP_XOR_QUAD_CurrentVersionRun_db62 {
  strings:
    $key_db62 = { 88 0d [2] ac 03 [2] 87 2f [2] a9 0d [2] bd 16 [2] b2 0c [2] ac 11 [2] ae 10 [2] b5 16 [2] a9 11 [2] b5 3e }

  condition:
    any of them
}