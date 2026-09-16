rule TTP_XOR_QUAD_CurrentVersionRun_d2dc {
  strings:
    $key_d2dc = { 81 b3 [2] a5 bd [2] 8e 91 [2] a0 b3 [2] b4 a8 [2] bb b2 [2] a5 af [2] a7 ae [2] bc a8 [2] a0 af [2] bc 80 }

  condition:
    any of them
}