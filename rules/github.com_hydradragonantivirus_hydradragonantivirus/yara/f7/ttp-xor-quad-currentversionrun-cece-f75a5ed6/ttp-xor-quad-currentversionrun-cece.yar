rule TTP_XOR_QUAD_CurrentVersionRun_cece {
  strings:
    $key_cece = { 9d a1 [2] b9 af [2] 92 83 [2] bc a1 [2] a8 ba [2] a7 a0 [2] b9 bd [2] bb bc [2] a0 ba [2] bc bd [2] a0 92 }

  condition:
    any of them
}