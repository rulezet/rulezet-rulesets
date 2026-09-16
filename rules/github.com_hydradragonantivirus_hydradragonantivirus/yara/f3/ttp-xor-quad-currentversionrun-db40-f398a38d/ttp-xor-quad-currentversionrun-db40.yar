rule TTP_XOR_QUAD_CurrentVersionRun_db40 {
  strings:
    $key_db40 = { 88 2f [2] ac 21 [2] 87 0d [2] a9 2f [2] bd 34 [2] b2 2e [2] ac 33 [2] ae 32 [2] b5 34 [2] a9 33 [2] b5 1c }

  condition:
    any of them
}