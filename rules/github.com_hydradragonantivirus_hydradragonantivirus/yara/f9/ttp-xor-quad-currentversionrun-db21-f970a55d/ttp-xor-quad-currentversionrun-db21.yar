rule TTP_XOR_QUAD_CurrentVersionRun_db21 {
  strings:
    $key_db21 = { 88 4e [2] ac 40 [2] 87 6c [2] a9 4e [2] bd 55 [2] b2 4f [2] ac 52 [2] ae 53 [2] b5 55 [2] a9 52 [2] b5 7d }

  condition:
    any of them
}