rule TTP_XOR_QUAD_CurrentVersionRun_d61e {
  strings:
    $key_d61e = { 85 71 [2] a1 7f [2] 8a 53 [2] a4 71 [2] b0 6a [2] bf 70 [2] a1 6d [2] a3 6c [2] b8 6a [2] a4 6d [2] b8 42 }

  condition:
    any of them
}