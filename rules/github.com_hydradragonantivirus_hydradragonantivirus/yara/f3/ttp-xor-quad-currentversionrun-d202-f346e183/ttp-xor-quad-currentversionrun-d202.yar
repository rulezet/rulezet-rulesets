rule TTP_XOR_QUAD_CurrentVersionRun_d202 {
  strings:
    $key_d202 = { 81 6d [2] a5 63 [2] 8e 4f [2] a0 6d [2] b4 76 [2] bb 6c [2] a5 71 [2] a7 70 [2] bc 76 [2] a0 71 [2] bc 5e }

  condition:
    any of them
}