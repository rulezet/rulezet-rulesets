rule TTP_XOR_QUAD_CurrentVersionRun_c001 {
  strings:
    $key_c001 = { 93 6e [2] b7 60 [2] 9c 4c [2] b2 6e [2] a6 75 [2] a9 6f [2] b7 72 [2] b5 73 [2] ae 75 [2] b2 72 [2] ae 5d }

  condition:
    any of them
}