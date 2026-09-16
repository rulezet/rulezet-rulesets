rule TTP_XOR_QUAD_CurrentVersionRun_a952 {
  strings:
    $key_a952 = { fa 3d [2] de 33 [2] f5 1f [2] db 3d [2] cf 26 [2] c0 3c [2] de 21 [2] dc 20 [2] c7 26 [2] db 21 [2] c7 0e }

  condition:
    any of them
}