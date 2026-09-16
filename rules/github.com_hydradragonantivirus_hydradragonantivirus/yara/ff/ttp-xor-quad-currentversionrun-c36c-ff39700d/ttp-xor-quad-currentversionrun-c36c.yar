rule TTP_XOR_QUAD_CurrentVersionRun_c36c {
  strings:
    $key_c36c = { 90 03 [2] b4 0d [2] 9f 21 [2] b1 03 [2] a5 18 [2] aa 02 [2] b4 1f [2] b6 1e [2] ad 18 [2] b1 1f [2] ad 30 }

  condition:
    any of them
}