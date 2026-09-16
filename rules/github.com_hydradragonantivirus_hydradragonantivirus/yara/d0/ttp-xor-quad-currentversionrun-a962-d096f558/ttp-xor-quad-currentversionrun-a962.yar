rule TTP_XOR_QUAD_CurrentVersionRun_a962 {
  strings:
    $key_a962 = { fa 0d [2] de 03 [2] f5 2f [2] db 0d [2] cf 16 [2] c0 0c [2] de 11 [2] dc 10 [2] c7 16 [2] db 11 [2] c7 3e }

  condition:
    any of them
}