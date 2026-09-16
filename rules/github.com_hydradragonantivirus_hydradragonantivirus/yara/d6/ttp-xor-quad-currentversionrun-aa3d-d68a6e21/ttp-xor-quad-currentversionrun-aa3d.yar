rule TTP_XOR_QUAD_CurrentVersionRun_aa3d {
  strings:
    $key_aa3d = { f9 52 [2] dd 5c [2] f6 70 [2] d8 52 [2] cc 49 [2] c3 53 [2] dd 4e [2] df 4f [2] c4 49 [2] d8 4e [2] c4 61 }

  condition:
    any of them
}