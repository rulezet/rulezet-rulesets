rule TTP_XOR_QUAD_CurrentVersionRun_c36d {
  strings:
    $key_c36d = { 90 02 [2] b4 0c [2] 9f 20 [2] b1 02 [2] a5 19 [2] aa 03 [2] b4 1e [2] b6 1f [2] ad 19 [2] b1 1e [2] ad 31 }

  condition:
    any of them
}