rule TTP_XOR_QUAD_CurrentVersionRun_ae5e {
  strings:
    $key_ae5e = { fd 31 [2] d9 3f [2] f2 13 [2] dc 31 [2] c8 2a [2] c7 30 [2] d9 2d [2] db 2c [2] c0 2a [2] dc 2d [2] c0 02 }

  condition:
    any of them
}