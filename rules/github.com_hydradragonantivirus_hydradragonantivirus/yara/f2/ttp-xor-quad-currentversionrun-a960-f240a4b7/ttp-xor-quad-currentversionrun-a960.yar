rule TTP_XOR_QUAD_CurrentVersionRun_a960 {
  strings:
    $key_a960 = { fa 0f [2] de 01 [2] f5 2d [2] db 0f [2] cf 14 [2] c0 0e [2] de 13 [2] dc 12 [2] c7 14 [2] db 13 [2] c7 3c }

  condition:
    any of them
}