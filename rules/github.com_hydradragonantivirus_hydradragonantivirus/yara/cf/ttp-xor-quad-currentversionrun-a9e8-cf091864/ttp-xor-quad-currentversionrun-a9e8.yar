rule TTP_XOR_QUAD_CurrentVersionRun_a9e8 {
  strings:
    $key_a9e8 = { fa 87 [2] de 89 [2] f5 a5 [2] db 87 [2] cf 9c [2] c0 86 [2] de 9b [2] dc 9a [2] c7 9c [2] db 9b [2] c7 b4 }

  condition:
    any of them
}