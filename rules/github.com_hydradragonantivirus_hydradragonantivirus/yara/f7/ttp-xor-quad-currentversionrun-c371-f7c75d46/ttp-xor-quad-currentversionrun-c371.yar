rule TTP_XOR_QUAD_CurrentVersionRun_c371 {
  strings:
    $key_c371 = { 90 1e [2] b4 10 [2] 9f 3c [2] b1 1e [2] a5 05 [2] aa 1f [2] b4 02 [2] b6 03 [2] ad 05 [2] b1 02 [2] ad 2d }

  condition:
    any of them
}