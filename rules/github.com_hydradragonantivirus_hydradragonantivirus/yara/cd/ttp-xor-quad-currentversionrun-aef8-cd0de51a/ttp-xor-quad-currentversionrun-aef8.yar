rule TTP_XOR_QUAD_CurrentVersionRun_aef8 {
  strings:
    $key_aef8 = { fd 97 [2] d9 99 [2] f2 b5 [2] dc 97 [2] c8 8c [2] c7 96 [2] d9 8b [2] db 8a [2] c0 8c [2] dc 8b [2] c0 a4 }

  condition:
    any of them
}