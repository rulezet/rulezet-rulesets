rule TTP_XOR_QUAD_CurrentVersionRun_df3e {
  strings:
    $key_df3e = { 8c 51 [2] a8 5f [2] 83 73 [2] ad 51 [2] b9 4a [2] b6 50 [2] a8 4d [2] aa 4c [2] b1 4a [2] ad 4d [2] b1 62 }

  condition:
    any of them
}