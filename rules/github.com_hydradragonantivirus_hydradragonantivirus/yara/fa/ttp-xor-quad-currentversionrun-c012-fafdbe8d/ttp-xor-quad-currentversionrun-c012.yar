rule TTP_XOR_QUAD_CurrentVersionRun_c012 {
  strings:
    $key_c012 = { 93 7d [2] b7 73 [2] 9c 5f [2] b2 7d [2] a6 66 [2] a9 7c [2] b7 61 [2] b5 60 [2] ae 66 [2] b2 61 [2] ae 4e }

  condition:
    any of them
}