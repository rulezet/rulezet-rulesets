rule TTP_XOR_QUAD_CurrentVersionRun_ae46 {
  strings:
    $key_ae46 = { fd 29 [2] d9 27 [2] f2 0b [2] dc 29 [2] c8 32 [2] c7 28 [2] d9 35 [2] db 34 [2] c0 32 [2] dc 35 [2] c0 1a }

  condition:
    any of them
}