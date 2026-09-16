rule TTP_XOR_QUAD_CurrentVersionRun_ae25 {
  strings:
    $key_ae25 = { fd 4a [2] d9 44 [2] f2 68 [2] dc 4a [2] c8 51 [2] c7 4b [2] d9 56 [2] db 57 [2] c0 51 [2] dc 56 [2] c0 79 }

  condition:
    any of them
}