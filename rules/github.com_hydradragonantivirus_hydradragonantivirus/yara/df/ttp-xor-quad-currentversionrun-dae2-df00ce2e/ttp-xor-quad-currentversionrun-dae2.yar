rule TTP_XOR_QUAD_CurrentVersionRun_dae2 {
  strings:
    $key_dae2 = { 89 8d [2] ad 83 [2] 86 af [2] a8 8d [2] bc 96 [2] b3 8c [2] ad 91 [2] af 90 [2] b4 96 [2] a8 91 [2] b4 be }

  condition:
    any of them
}