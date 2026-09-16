rule TTP_XOR_QUAD_CurrentVersionRun_ae64 {
  strings:
    $key_ae64 = { fd 0b [2] d9 05 [2] f2 29 [2] dc 0b [2] c8 10 [2] c7 0a [2] d9 17 [2] db 16 [2] c0 10 [2] dc 17 [2] c0 38 }

  condition:
    any of them
}