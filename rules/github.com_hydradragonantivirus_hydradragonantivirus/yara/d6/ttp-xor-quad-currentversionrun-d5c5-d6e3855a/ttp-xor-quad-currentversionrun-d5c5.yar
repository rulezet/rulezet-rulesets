rule TTP_XOR_QUAD_CurrentVersionRun_d5c5 {
  strings:
    $key_d5c5 = { 86 aa [2] a2 a4 [2] 89 88 [2] a7 aa [2] b3 b1 [2] bc ab [2] a2 b6 [2] a0 b7 [2] bb b1 [2] a7 b6 [2] bb 99 }

  condition:
    any of them
}