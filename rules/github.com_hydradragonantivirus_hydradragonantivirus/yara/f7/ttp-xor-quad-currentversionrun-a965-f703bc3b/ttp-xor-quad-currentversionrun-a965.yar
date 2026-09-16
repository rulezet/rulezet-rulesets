rule TTP_XOR_QUAD_CurrentVersionRun_a965 {
  strings:
    $key_a965 = { fa 0a [2] de 04 [2] f5 28 [2] db 0a [2] cf 11 [2] c0 0b [2] de 16 [2] dc 17 [2] c7 11 [2] db 16 [2] c7 39 }

  condition:
    any of them
}