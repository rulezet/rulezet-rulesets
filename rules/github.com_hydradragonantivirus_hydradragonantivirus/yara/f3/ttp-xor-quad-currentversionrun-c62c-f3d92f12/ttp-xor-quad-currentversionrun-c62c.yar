rule TTP_XOR_QUAD_CurrentVersionRun_c62c {
  strings:
    $key_c62c = { 95 43 [2] b1 4d [2] 9a 61 [2] b4 43 [2] a0 58 [2] af 42 [2] b1 5f [2] b3 5e [2] a8 58 [2] b4 5f [2] a8 70 }

  condition:
    any of them
}