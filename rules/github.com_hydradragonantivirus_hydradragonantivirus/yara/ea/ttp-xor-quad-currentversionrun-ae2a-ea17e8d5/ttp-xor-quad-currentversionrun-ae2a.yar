rule TTP_XOR_QUAD_CurrentVersionRun_ae2a {
  strings:
    $key_ae2a = { fd 45 [2] d9 4b [2] f2 67 [2] dc 45 [2] c8 5e [2] c7 44 [2] d9 59 [2] db 58 [2] c0 5e [2] dc 59 [2] c0 76 }

  condition:
    any of them
}