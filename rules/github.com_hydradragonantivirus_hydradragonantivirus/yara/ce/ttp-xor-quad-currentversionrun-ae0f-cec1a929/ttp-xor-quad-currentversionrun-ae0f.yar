rule TTP_XOR_QUAD_CurrentVersionRun_ae0f {
  strings:
    $key_ae0f = { fd 60 [2] d9 6e [2] f2 42 [2] dc 60 [2] c8 7b [2] c7 61 [2] d9 7c [2] db 7d [2] c0 7b [2] dc 7c [2] c0 53 }

  condition:
    any of them
}