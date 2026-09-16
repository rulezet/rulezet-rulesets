rule TTP_XOR_QUAD_CurrentVersionRun_d2f0 {
  strings:
    $key_d2f0 = { 81 9f [2] a5 91 [2] 8e bd [2] a0 9f [2] b4 84 [2] bb 9e [2] a5 83 [2] a7 82 [2] bc 84 [2] a0 83 [2] bc ac }

  condition:
    any of them
}