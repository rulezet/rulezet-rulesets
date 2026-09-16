rule TTP_XOR_QUAD_CurrentVersionRun_ae36 {
  strings:
    $key_ae36 = { fd 59 [2] d9 57 [2] f2 7b [2] dc 59 [2] c8 42 [2] c7 58 [2] d9 45 [2] db 44 [2] c0 42 [2] dc 45 [2] c0 6a }

  condition:
    any of them
}