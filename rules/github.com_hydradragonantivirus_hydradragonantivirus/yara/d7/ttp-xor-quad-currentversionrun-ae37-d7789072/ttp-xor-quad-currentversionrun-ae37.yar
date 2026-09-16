rule TTP_XOR_QUAD_CurrentVersionRun_ae37 {
  strings:
    $key_ae37 = { fd 58 [2] d9 56 [2] f2 7a [2] dc 58 [2] c8 43 [2] c7 59 [2] d9 44 [2] db 45 [2] c0 43 [2] dc 44 [2] c0 6b }

  condition:
    any of them
}