rule TTP_XOR_QUAD_CurrentVersionRun_c671 {
  strings:
    $key_c671 = { 95 1e [2] b1 10 [2] 9a 3c [2] b4 1e [2] a0 05 [2] af 1f [2] b1 02 [2] b3 03 [2] a8 05 [2] b4 02 [2] a8 2d }

  condition:
    any of them
}