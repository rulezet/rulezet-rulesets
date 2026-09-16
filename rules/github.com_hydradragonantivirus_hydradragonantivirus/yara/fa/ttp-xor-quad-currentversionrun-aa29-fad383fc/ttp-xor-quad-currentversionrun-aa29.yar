rule TTP_XOR_QUAD_CurrentVersionRun_aa29 {
  strings:
    $key_aa29 = { f9 46 [2] dd 48 [2] f6 64 [2] d8 46 [2] cc 5d [2] c3 47 [2] dd 5a [2] df 5b [2] c4 5d [2] d8 5a [2] c4 75 }

  condition:
    any of them
}