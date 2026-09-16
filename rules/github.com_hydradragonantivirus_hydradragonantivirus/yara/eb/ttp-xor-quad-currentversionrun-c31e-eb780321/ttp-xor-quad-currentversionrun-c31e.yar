rule TTP_XOR_QUAD_CurrentVersionRun_c31e {
  strings:
    $key_c31e = { 90 71 [2] b4 7f [2] 9f 53 [2] b1 71 [2] a5 6a [2] aa 70 [2] b4 6d [2] b6 6c [2] ad 6a [2] b1 6d [2] ad 42 }

  condition:
    any of them
}