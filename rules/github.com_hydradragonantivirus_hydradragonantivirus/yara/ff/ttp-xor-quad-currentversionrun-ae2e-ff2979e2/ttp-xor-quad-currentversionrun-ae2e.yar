rule TTP_XOR_QUAD_CurrentVersionRun_ae2e {
  strings:
    $key_ae2e = { fd 41 [2] d9 4f [2] f2 63 [2] dc 41 [2] c8 5a [2] c7 40 [2] d9 5d [2] db 5c [2] c0 5a [2] dc 5d [2] c0 72 }

  condition:
    any of them
}