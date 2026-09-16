rule TTP_XOR_QUAD_CurrentVersionRun_a9f8 {
  strings:
    $key_a9f8 = { fa 97 [2] de 99 [2] f5 b5 [2] db 97 [2] cf 8c [2] c0 96 [2] de 8b [2] dc 8a [2] c7 8c [2] db 8b [2] c7 a4 }

  condition:
    any of them
}