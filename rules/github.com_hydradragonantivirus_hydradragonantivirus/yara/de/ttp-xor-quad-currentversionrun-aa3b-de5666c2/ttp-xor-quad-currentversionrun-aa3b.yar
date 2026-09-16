rule TTP_XOR_QUAD_CurrentVersionRun_aa3b {
  strings:
    $key_aa3b = { f9 54 [2] dd 5a [2] f6 76 [2] d8 54 [2] cc 4f [2] c3 55 [2] dd 48 [2] df 49 [2] c4 4f [2] d8 48 [2] c4 67 }

  condition:
    any of them
}