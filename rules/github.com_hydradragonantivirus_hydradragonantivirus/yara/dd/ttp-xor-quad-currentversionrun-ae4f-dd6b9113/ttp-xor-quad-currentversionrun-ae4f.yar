rule TTP_XOR_QUAD_CurrentVersionRun_ae4f {
  strings:
    $key_ae4f = { fd 20 [2] d9 2e [2] f2 02 [2] dc 20 [2] c8 3b [2] c7 21 [2] d9 3c [2] db 3d [2] c0 3b [2] dc 3c [2] c0 13 }

  condition:
    any of them
}