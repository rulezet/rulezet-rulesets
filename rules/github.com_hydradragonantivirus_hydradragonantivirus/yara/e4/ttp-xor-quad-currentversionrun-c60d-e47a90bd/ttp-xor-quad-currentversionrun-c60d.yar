rule TTP_XOR_QUAD_CurrentVersionRun_c60d {
  strings:
    $key_c60d = { 95 62 [2] b1 6c [2] 9a 40 [2] b4 62 [2] a0 79 [2] af 63 [2] b1 7e [2] b3 7f [2] a8 79 [2] b4 7e [2] a8 51 }

  condition:
    any of them
}