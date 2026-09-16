rule TTP_XOR_QUAD_CurrentVersionRun_c02d {
  strings:
    $key_c02d = { 93 42 [2] b7 4c [2] 9c 60 [2] b2 42 [2] a6 59 [2] a9 43 [2] b7 5e [2] b5 5f [2] ae 59 [2] b2 5e [2] ae 71 }

  condition:
    any of them
}