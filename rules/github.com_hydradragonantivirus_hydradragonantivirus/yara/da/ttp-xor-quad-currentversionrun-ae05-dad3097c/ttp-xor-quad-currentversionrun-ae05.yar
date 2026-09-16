rule TTP_XOR_QUAD_CurrentVersionRun_ae05 {
  strings:
    $key_ae05 = { fd 6a [2] d9 64 [2] f2 48 [2] dc 6a [2] c8 71 [2] c7 6b [2] d9 76 [2] db 77 [2] c0 71 [2] dc 76 [2] c0 59 }

  condition:
    any of them
}