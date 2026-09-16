rule TTP_XOR_QUAD_CurrentVersionRun_a97d {
  strings:
    $key_a97d = { fa 12 [2] de 1c [2] f5 30 [2] db 12 [2] cf 09 [2] c0 13 [2] de 0e [2] dc 0f [2] c7 09 [2] db 0e [2] c7 21 }

  condition:
    any of them
}