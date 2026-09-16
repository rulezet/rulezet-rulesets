rule TTP_XOR_QUAD_CurrentVersionRun_a96e {
  strings:
    $key_a96e = { fa 01 [2] de 0f [2] f5 23 [2] db 01 [2] cf 1a [2] c0 00 [2] de 1d [2] dc 1c [2] c7 1a [2] db 1d [2] c7 32 }

  condition:
    any of them
}