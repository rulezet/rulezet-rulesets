rule TTP_XOR_QUAD_CurrentVersionRun_d2e2 {
  strings:
    $key_d2e2 = { 81 8d [2] a5 83 [2] 8e af [2] a0 8d [2] b4 96 [2] bb 8c [2] a5 91 [2] a7 90 [2] bc 96 [2] a0 91 [2] bc be }

  condition:
    any of them
}