rule TTP_XOR_QUAD_CurrentVersionRun_aa01 {
  strings:
    $key_aa01 = { f9 6e [2] dd 60 [2] f6 4c [2] d8 6e [2] cc 75 [2] c3 6f [2] dd 72 [2] df 73 [2] c4 75 [2] d8 72 [2] c4 5d }

  condition:
    any of them
}