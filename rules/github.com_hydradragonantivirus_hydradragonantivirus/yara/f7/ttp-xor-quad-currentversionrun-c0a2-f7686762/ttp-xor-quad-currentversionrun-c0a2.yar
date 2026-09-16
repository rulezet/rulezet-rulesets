rule TTP_XOR_QUAD_CurrentVersionRun_c0a2 {
  strings:
    $key_c0a2 = { 93 cd [2] b7 c3 [2] 9c ef [2] b2 cd [2] a6 d6 [2] a9 cc [2] b7 d1 [2] b5 d0 [2] ae d6 [2] b2 d1 [2] ae fe }

  condition:
    any of them
}