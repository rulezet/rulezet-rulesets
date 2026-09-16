rule TTP_XOR_QUAD_CurrentVersionRun_aeed {
  strings:
    $key_aeed = { fd 82 [2] d9 8c [2] f2 a0 [2] dc 82 [2] c8 99 [2] c7 83 [2] d9 9e [2] db 9f [2] c0 99 [2] dc 9e [2] c0 b1 }

  condition:
    any of them
}