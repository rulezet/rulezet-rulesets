rule TTP_XOR_QUAD_CurrentVersionRun_c812 {
  strings:
    $key_c812 = { 9b 7d [2] bf 73 [2] 94 5f [2] ba 7d [2] ae 66 [2] a1 7c [2] bf 61 [2] bd 60 [2] a6 66 [2] ba 61 [2] a6 4e }

  condition:
    any of them
}