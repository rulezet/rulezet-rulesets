rule TTP_XOR_QUAD_CurrentVersionRun_a95c {
  strings:
    $key_a95c = { fa 33 [2] de 3d [2] f5 11 [2] db 33 [2] cf 28 [2] c0 32 [2] de 2f [2] dc 2e [2] c7 28 [2] db 2f [2] c7 00 }

  condition:
    any of them
}