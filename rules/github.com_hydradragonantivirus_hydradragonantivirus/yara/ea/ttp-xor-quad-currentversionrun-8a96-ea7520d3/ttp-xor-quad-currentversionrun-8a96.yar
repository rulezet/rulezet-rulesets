rule TTP_XOR_QUAD_CurrentVersionRun_8a96 {
  strings:
    $key_8a96 = { d9 f9 [2] fd f7 [2] d6 db [2] f8 f9 [2] ec e2 [2] e3 f8 [2] fd e5 [2] ff e4 [2] e4 e2 [2] f8 e5 [2] e4 ca }

  condition:
    any of them
}