rule TTP_XOR_QUAD_CurrentVersionRun_a9e4 {
  strings:
    $key_a9e4 = { fa 8b [2] de 85 [2] f5 a9 [2] db 8b [2] cf 90 [2] c0 8a [2] de 97 [2] dc 96 [2] c7 90 [2] db 97 [2] c7 b8 }

  condition:
    any of them
}