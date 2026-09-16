rule TTP_XOR_QUAD_CurrentVersionRun_c15d {
  strings:
    $key_c15d = { 92 32 [2] b6 3c [2] 9d 10 [2] b3 32 [2] a7 29 [2] a8 33 [2] b6 2e [2] b4 2f [2] af 29 [2] b3 2e [2] af 01 }

  condition:
    any of them
}