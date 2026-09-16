rule TTP_XOR_QUAD_CurrentVersionRun_c8f7 {
  strings:
    $key_c8f7 = { 9b 98 [2] bf 96 [2] 94 ba [2] ba 98 [2] ae 83 [2] a1 99 [2] bf 84 [2] bd 85 [2] a6 83 [2] ba 84 [2] a6 ab }

  condition:
    any of them
}