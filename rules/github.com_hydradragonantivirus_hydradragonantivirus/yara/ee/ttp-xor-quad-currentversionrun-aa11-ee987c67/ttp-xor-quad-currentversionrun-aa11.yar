rule TTP_XOR_QUAD_CurrentVersionRun_aa11 {
  strings:
    $key_aa11 = { f9 7e [2] dd 70 [2] f6 5c [2] d8 7e [2] cc 65 [2] c3 7f [2] dd 62 [2] df 63 [2] c4 65 [2] d8 62 [2] c4 4d }

  condition:
    any of them
}