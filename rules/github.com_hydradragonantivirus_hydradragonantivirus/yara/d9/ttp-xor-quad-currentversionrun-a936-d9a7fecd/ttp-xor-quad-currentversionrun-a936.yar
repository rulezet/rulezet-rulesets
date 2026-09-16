rule TTP_XOR_QUAD_CurrentVersionRun_a936 {
  strings:
    $key_a936 = { fa 59 [2] de 57 [2] f5 7b [2] db 59 [2] cf 42 [2] c0 58 [2] de 45 [2] dc 44 [2] c7 42 [2] db 45 [2] c7 6a }

  condition:
    any of them
}