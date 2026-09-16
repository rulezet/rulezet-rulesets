rule TTP_XOR_QUAD_CurrentVersionRun_ae52 {
  strings:
    $key_ae52 = { fd 3d [2] d9 33 [2] f2 1f [2] dc 3d [2] c8 26 [2] c7 3c [2] d9 21 [2] db 20 [2] c0 26 [2] dc 21 [2] c0 0e }

  condition:
    any of them
}