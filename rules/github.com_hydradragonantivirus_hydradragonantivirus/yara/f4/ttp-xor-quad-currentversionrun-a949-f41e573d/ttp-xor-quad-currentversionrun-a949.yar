rule TTP_XOR_QUAD_CurrentVersionRun_a949 {
  strings:
    $key_a949 = { fa 26 [2] de 28 [2] f5 04 [2] db 26 [2] cf 3d [2] c0 27 [2] de 3a [2] dc 3b [2] c7 3d [2] db 3a [2] c7 15 }

  condition:
    any of them
}