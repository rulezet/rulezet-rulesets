rule TTP_XOR_QUAD_CurrentVersionRun_c6fe {
  strings:
    $key_c6fe = { 95 91 [2] b1 9f [2] 9a b3 [2] b4 91 [2] a0 8a [2] af 90 [2] b1 8d [2] b3 8c [2] a8 8a [2] b4 8d [2] a8 a2 }

  condition:
    any of them
}