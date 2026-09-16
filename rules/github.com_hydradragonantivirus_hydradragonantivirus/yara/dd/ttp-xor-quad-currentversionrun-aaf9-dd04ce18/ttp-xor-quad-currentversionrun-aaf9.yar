rule TTP_XOR_QUAD_CurrentVersionRun_aaf9 {
  strings:
    $key_aaf9 = { f9 96 [2] dd 98 [2] f6 b4 [2] d8 96 [2] cc 8d [2] c3 97 [2] dd 8a [2] df 8b [2] c4 8d [2] d8 8a [2] c4 a5 }

  condition:
    any of them
}