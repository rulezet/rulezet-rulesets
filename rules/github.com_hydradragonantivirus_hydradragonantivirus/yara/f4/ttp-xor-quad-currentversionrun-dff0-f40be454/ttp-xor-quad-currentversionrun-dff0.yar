rule TTP_XOR_QUAD_CurrentVersionRun_dff0 {
  strings:
    $key_dff0 = { 8c 9f [2] a8 91 [2] 83 bd [2] ad 9f [2] b9 84 [2] b6 9e [2] a8 83 [2] aa 82 [2] b1 84 [2] ad 83 [2] b1 ac }

  condition:
    any of them
}