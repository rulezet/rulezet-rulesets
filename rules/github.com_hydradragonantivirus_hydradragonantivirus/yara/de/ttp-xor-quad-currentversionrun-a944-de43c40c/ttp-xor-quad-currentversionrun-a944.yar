rule TTP_XOR_QUAD_CurrentVersionRun_a944 {
  strings:
    $key_a944 = { fa 2b [2] de 25 [2] f5 09 [2] db 2b [2] cf 30 [2] c0 2a [2] de 37 [2] dc 36 [2] c7 30 [2] db 37 [2] c7 18 }

  condition:
    any of them
}