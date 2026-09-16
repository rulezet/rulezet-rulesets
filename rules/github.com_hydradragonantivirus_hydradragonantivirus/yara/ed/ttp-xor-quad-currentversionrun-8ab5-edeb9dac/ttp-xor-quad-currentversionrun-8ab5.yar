rule TTP_XOR_QUAD_CurrentVersionRun_8ab5 {
  strings:
    $key_8ab5 = { d9 da [2] fd d4 [2] d6 f8 [2] f8 da [2] ec c1 [2] e3 db [2] fd c6 [2] ff c7 [2] e4 c1 [2] f8 c6 [2] e4 e9 }

  condition:
    any of them
}