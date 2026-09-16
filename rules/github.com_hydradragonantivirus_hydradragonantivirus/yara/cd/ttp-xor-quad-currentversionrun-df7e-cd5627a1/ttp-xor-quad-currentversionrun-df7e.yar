rule TTP_XOR_QUAD_CurrentVersionRun_df7e {
  strings:
    $key_df7e = { 8c 11 [2] a8 1f [2] 83 33 [2] ad 11 [2] b9 0a [2] b6 10 [2] a8 0d [2] aa 0c [2] b1 0a [2] ad 0d [2] b1 22 }

  condition:
    any of them
}