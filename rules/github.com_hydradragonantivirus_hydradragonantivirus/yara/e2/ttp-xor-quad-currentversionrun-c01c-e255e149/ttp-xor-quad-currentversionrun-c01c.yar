rule TTP_XOR_QUAD_CurrentVersionRun_c01c {
  strings:
    $key_c01c = { 93 73 [2] b7 7d [2] 9c 51 [2] b2 73 [2] a6 68 [2] a9 72 [2] b7 6f [2] b5 6e [2] ae 68 [2] b2 6f [2] ae 40 }

  condition:
    any of them
}