rule TTP_XOR_QUAD_CurrentVersionRun_ae7e {
  strings:
    $key_ae7e = { fd 11 [2] d9 1f [2] f2 33 [2] dc 11 [2] c8 0a [2] c7 10 [2] d9 0d [2] db 0c [2] c0 0a [2] dc 0d [2] c0 22 }

  condition:
    any of them
}