rule TTP_XOR_QUAD_CurrentVersionRun_c341 {
  strings:
    $key_c341 = { 90 2e [2] b4 20 [2] 9f 0c [2] b1 2e [2] a5 35 [2] aa 2f [2] b4 32 [2] b6 33 [2] ad 35 [2] b1 32 [2] ad 1d }

  condition:
    any of them
}