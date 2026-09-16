rule TTP_XOR_QUAD_CurrentVersionRun_db30 {
  strings:
    $key_db30 = { 88 5f [2] ac 51 [2] 87 7d [2] a9 5f [2] bd 44 [2] b2 5e [2] ac 43 [2] ae 42 [2] b5 44 [2] a9 43 [2] b5 6c }

  condition:
    any of them
}