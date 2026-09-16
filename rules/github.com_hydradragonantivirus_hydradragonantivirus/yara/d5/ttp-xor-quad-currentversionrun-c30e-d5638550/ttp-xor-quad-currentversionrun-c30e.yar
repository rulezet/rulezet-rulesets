rule TTP_XOR_QUAD_CurrentVersionRun_c30e {
  strings:
    $key_c30e = { 90 61 [2] b4 6f [2] 9f 43 [2] b1 61 [2] a5 7a [2] aa 60 [2] b4 7d [2] b6 7c [2] ad 7a [2] b1 7d [2] ad 52 }

  condition:
    any of them
}