rule TTP_XOR_QUAD_CurrentVersionRun_ae7a {
  strings:
    $key_ae7a = { fd 15 [2] d9 1b [2] f2 37 [2] dc 15 [2] c8 0e [2] c7 14 [2] d9 09 [2] db 08 [2] c0 0e [2] dc 09 [2] c0 26 }

  condition:
    any of them
}