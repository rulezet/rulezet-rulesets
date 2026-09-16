rule TTP_XOR_QUAD_CurrentVersionRun_ae43 {
  strings:
    $key_ae43 = { fd 2c [2] d9 22 [2] f2 0e [2] dc 2c [2] c8 37 [2] c7 2d [2] d9 30 [2] db 31 [2] c0 37 [2] dc 30 [2] c0 1f }

  condition:
    any of them
}