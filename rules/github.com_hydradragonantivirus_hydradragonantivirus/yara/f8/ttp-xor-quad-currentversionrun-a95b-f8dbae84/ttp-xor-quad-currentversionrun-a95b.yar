rule TTP_XOR_QUAD_CurrentVersionRun_a95b {
  strings:
    $key_a95b = { fa 34 [2] de 3a [2] f5 16 [2] db 34 [2] cf 2f [2] c0 35 [2] de 28 [2] dc 29 [2] c7 2f [2] db 28 [2] c7 07 }

  condition:
    any of them
}