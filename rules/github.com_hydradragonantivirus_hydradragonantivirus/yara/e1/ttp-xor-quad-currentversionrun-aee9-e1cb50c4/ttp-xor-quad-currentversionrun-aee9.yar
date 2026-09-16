rule TTP_XOR_QUAD_CurrentVersionRun_aee9 {
  strings:
    $key_aee9 = { fd 86 [2] d9 88 [2] f2 a4 [2] dc 86 [2] c8 9d [2] c7 87 [2] d9 9a [2] db 9b [2] c0 9d [2] dc 9a [2] c0 b5 }

  condition:
    any of them
}