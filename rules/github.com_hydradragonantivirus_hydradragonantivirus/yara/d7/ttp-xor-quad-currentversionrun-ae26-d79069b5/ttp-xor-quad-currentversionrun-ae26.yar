rule TTP_XOR_QUAD_CurrentVersionRun_ae26 {
  strings:
    $key_ae26 = { fd 49 [2] d9 47 [2] f2 6b [2] dc 49 [2] c8 52 [2] c7 48 [2] d9 55 [2] db 54 [2] c0 52 [2] dc 55 [2] c0 7a }

  condition:
    any of them
}