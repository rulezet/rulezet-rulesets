rule TTP_XOR_QUAD_CurrentVersionRun_daec {
  strings:
    $key_daec = { 89 83 [2] ad 8d [2] 86 a1 [2] a8 83 [2] bc 98 [2] b3 82 [2] ad 9f [2] af 9e [2] b4 98 [2] a8 9f [2] b4 b0 }

  condition:
    any of them
}