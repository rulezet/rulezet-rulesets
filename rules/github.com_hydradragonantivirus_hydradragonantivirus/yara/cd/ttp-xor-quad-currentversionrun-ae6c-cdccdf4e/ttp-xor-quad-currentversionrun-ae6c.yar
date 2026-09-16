rule TTP_XOR_QUAD_CurrentVersionRun_ae6c {
  strings:
    $key_ae6c = { fd 03 [2] d9 0d [2] f2 21 [2] dc 03 [2] c8 18 [2] c7 02 [2] d9 1f [2] db 1e [2] c0 18 [2] dc 1f [2] c0 30 }

  condition:
    any of them
}