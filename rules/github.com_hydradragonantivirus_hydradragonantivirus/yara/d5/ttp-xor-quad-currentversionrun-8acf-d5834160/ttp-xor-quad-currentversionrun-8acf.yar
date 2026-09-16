rule TTP_XOR_QUAD_CurrentVersionRun_8acf {
  strings:
    $key_8acf = { d9 a0 [2] fd ae [2] d6 82 [2] f8 a0 [2] ec bb [2] e3 a1 [2] fd bc [2] ff bd [2] e4 bb [2] f8 bc [2] e4 93 }

  condition:
    any of them
}