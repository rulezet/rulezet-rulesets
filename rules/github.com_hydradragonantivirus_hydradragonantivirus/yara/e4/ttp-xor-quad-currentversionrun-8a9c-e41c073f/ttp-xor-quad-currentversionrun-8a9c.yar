rule TTP_XOR_QUAD_CurrentVersionRun_8a9c {
  strings:
    $key_8a9c = { d9 f3 [2] fd fd [2] d6 d1 [2] f8 f3 [2] ec e8 [2] e3 f2 [2] fd ef [2] ff ee [2] e4 e8 [2] f8 ef [2] e4 c0 }

  condition:
    any of them
}