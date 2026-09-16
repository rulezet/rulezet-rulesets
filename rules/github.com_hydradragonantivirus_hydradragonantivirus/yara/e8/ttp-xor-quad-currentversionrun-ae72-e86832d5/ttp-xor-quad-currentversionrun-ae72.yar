rule TTP_XOR_QUAD_CurrentVersionRun_ae72 {
  strings:
    $key_ae72 = { fd 1d [2] d9 13 [2] f2 3f [2] dc 1d [2] c8 06 [2] c7 1c [2] d9 01 [2] db 00 [2] c0 06 [2] dc 01 [2] c0 2e }

  condition:
    any of them
}