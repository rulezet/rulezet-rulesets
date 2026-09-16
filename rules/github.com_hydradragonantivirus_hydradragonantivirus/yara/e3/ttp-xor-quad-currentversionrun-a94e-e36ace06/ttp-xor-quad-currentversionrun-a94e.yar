rule TTP_XOR_QUAD_CurrentVersionRun_a94e {
  strings:
    $key_a94e = { fa 21 [2] de 2f [2] f5 03 [2] db 21 [2] cf 3a [2] c0 20 [2] de 3d [2] dc 3c [2] c7 3a [2] db 3d [2] c7 12 }

  condition:
    any of them
}