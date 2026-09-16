rule TTP_XOR_QUAD_CurrentVersionRun_ae50 {
  strings:
    $key_ae50 = { fd 3f [2] d9 31 [2] f2 1d [2] dc 3f [2] c8 24 [2] c7 3e [2] d9 23 [2] db 22 [2] c0 24 [2] dc 23 [2] c0 0c }

  condition:
    any of them
}