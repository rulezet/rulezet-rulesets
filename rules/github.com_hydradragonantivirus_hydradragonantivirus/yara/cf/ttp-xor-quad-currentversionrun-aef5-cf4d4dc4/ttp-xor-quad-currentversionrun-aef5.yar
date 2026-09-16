rule TTP_XOR_QUAD_CurrentVersionRun_aef5 {
  strings:
    $key_aef5 = { fd 9a [2] d9 94 [2] f2 b8 [2] dc 9a [2] c8 81 [2] c7 9b [2] d9 86 [2] db 87 [2] c0 81 [2] dc 86 [2] c0 a9 }

  condition:
    any of them
}