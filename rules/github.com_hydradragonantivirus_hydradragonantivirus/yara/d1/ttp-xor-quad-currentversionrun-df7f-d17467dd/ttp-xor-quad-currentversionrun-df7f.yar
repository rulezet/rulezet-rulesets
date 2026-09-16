rule TTP_XOR_QUAD_CurrentVersionRun_df7f {
  strings:
    $key_df7f = { 8c 10 [2] a8 1e [2] 83 32 [2] ad 10 [2] b9 0b [2] b6 11 [2] a8 0c [2] aa 0d [2] b1 0b [2] ad 0c [2] b1 23 }

  condition:
    any of them
}