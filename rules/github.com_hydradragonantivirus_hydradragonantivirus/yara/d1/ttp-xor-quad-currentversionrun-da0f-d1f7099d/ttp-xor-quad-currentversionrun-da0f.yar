rule TTP_XOR_QUAD_CurrentVersionRun_da0f {
  strings:
    $key_da0f = { 89 60 [2] ad 6e [2] 86 42 [2] a8 60 [2] bc 7b [2] b3 61 [2] ad 7c [2] af 7d [2] b4 7b [2] a8 7c [2] b4 53 }

  condition:
    any of them
}