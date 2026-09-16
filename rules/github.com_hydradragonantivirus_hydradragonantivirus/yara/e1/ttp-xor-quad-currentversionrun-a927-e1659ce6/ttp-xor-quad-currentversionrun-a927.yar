rule TTP_XOR_QUAD_CurrentVersionRun_a927 {
  strings:
    $key_a927 = { fa 48 [2] de 46 [2] f5 6a [2] db 48 [2] cf 53 [2] c0 49 [2] de 54 [2] dc 55 [2] c7 53 [2] db 54 [2] c7 7b }

  condition:
    any of them
}