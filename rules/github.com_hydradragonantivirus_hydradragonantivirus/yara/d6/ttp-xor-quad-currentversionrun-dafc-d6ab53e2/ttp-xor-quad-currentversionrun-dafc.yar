rule TTP_XOR_QUAD_CurrentVersionRun_dafc {
  strings:
    $key_dafc = { 89 93 [2] ad 9d [2] 86 b1 [2] a8 93 [2] bc 88 [2] b3 92 [2] ad 8f [2] af 8e [2] b4 88 [2] a8 8f [2] b4 a0 }

  condition:
    any of them
}