rule TTP_XOR_QUAD_CurrentVersionRun_d5c2 {
  strings:
    $key_d5c2 = { 86 ad [2] a2 a3 [2] 89 8f [2] a7 ad [2] b3 b6 [2] bc ac [2] a2 b1 [2] a0 b0 [2] bb b6 [2] a7 b1 [2] bb 9e }

  condition:
    any of them
}