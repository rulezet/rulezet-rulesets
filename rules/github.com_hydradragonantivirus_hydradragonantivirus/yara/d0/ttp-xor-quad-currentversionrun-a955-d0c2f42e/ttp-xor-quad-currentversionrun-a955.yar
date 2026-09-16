rule TTP_XOR_QUAD_CurrentVersionRun_a955 {
  strings:
    $key_a955 = { fa 3a [2] de 34 [2] f5 18 [2] db 3a [2] cf 21 [2] c0 3b [2] de 26 [2] dc 27 [2] c7 21 [2] db 26 [2] c7 09 }

  condition:
    any of them
}