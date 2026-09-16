rule TTP_XOR_QUAD_CurrentVersionRun_8a93 {
  strings:
    $key_8a93 = { d9 fc [2] fd f2 [2] d6 de [2] f8 fc [2] ec e7 [2] e3 fd [2] fd e0 [2] ff e1 [2] e4 e7 [2] f8 e0 [2] e4 cf }

  condition:
    any of them
}