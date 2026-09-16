rule TTP_XOR_QUAD_CurrentVersionRun_a906 {
  strings:
    $key_a906 = { fa 69 [2] de 67 [2] f5 4b [2] db 69 [2] cf 72 [2] c0 68 [2] de 75 [2] dc 74 [2] c7 72 [2] db 75 [2] c7 5a }

  condition:
    any of them
}