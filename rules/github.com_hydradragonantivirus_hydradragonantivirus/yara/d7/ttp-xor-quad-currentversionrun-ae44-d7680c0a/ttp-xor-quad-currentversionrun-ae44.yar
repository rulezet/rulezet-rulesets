rule TTP_XOR_QUAD_CurrentVersionRun_ae44 {
  strings:
    $key_ae44 = { fd 2b [2] d9 25 [2] f2 09 [2] dc 2b [2] c8 30 [2] c7 2a [2] d9 37 [2] db 36 [2] c0 30 [2] dc 37 [2] c0 18 }

  condition:
    any of them
}