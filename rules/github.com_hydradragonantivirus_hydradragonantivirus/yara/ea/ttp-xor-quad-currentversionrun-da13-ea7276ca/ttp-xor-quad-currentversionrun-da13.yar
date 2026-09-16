rule TTP_XOR_QUAD_CurrentVersionRun_da13 {
  strings:
    $key_da13 = { 89 7c [2] ad 72 [2] 86 5e [2] a8 7c [2] bc 67 [2] b3 7d [2] ad 60 [2] af 61 [2] b4 67 [2] a8 60 [2] b4 4f }

  condition:
    any of them
}