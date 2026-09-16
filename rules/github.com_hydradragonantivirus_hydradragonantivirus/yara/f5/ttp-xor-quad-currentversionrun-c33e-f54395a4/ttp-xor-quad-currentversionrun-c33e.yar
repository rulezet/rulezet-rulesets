rule TTP_XOR_QUAD_CurrentVersionRun_c33e {
  strings:
    $key_c33e = { 90 51 [2] b4 5f [2] 9f 73 [2] b1 51 [2] a5 4a [2] aa 50 [2] b4 4d [2] b6 4c [2] ad 4a [2] b1 4d [2] ad 62 }

  condition:
    any of them
}