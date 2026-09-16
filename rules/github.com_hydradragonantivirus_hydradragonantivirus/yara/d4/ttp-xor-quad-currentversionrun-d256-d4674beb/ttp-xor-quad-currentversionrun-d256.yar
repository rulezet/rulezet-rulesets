rule TTP_XOR_QUAD_CurrentVersionRun_d256 {
  strings:
    $key_d256 = { 81 39 [2] a5 37 [2] 8e 1b [2] a0 39 [2] b4 22 [2] bb 38 [2] a5 25 [2] a7 24 [2] bc 22 [2] a0 25 [2] bc 0a }

  condition:
    any of them
}