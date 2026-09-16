rule TTP_XOR_QUAD_CurrentVersionRun_c32f {
  strings:
    $key_c32f = { 90 40 [2] b4 4e [2] 9f 62 [2] b1 40 [2] a5 5b [2] aa 41 [2] b4 5c [2] b6 5d [2] ad 5b [2] b1 5c [2] ad 73 }

  condition:
    any of them
}