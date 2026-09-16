rule TTP_XOR_QUAD_CurrentVersionRun_c662 {
  strings:
    $key_c662 = { 95 0d [2] b1 03 [2] 9a 2f [2] b4 0d [2] a0 16 [2] af 0c [2] b1 11 [2] b3 10 [2] a8 16 [2] b4 11 [2] a8 3e }

  condition:
    any of them
}