rule TTP_XOR_QUAD_CurrentVersionRun_aa7e {
  strings:
    $key_aa7e = { f9 11 [2] dd 1f [2] f6 33 [2] d8 11 [2] cc 0a [2] c3 10 [2] dd 0d [2] df 0c [2] c4 0a [2] d8 0d [2] c4 22 }

  condition:
    any of them
}