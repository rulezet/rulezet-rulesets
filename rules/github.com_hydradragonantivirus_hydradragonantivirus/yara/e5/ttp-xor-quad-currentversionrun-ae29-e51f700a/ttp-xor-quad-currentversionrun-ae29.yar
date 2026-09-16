rule TTP_XOR_QUAD_CurrentVersionRun_ae29 {
  strings:
    $key_ae29 = { fd 46 [2] d9 48 [2] f2 64 [2] dc 46 [2] c8 5d [2] c7 47 [2] d9 5a [2] db 5b [2] c0 5d [2] dc 5a [2] c0 75 }

  condition:
    any of them
}