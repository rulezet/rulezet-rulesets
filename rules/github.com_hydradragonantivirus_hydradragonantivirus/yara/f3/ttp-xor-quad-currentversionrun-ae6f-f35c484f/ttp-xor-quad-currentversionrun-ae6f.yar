rule TTP_XOR_QUAD_CurrentVersionRun_ae6f {
  strings:
    $key_ae6f = { fd 00 [2] d9 0e [2] f2 22 [2] dc 00 [2] c8 1b [2] c7 01 [2] d9 1c [2] db 1d [2] c0 1b [2] dc 1c [2] c0 33 }

  condition:
    any of them
}