rule TTP_XOR_QUAD_CurrentVersionRun_c32c {
  strings:
    $key_c32c = { 90 43 [2] b4 4d [2] 9f 61 [2] b1 43 [2] a5 58 [2] aa 42 [2] b4 5f [2] b6 5e [2] ad 58 [2] b1 5f [2] ad 70 }

  condition:
    any of them
}