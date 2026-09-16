rule TTP_XOR_QUAD_CurrentVersionRun_d24f {
  strings:
    $key_d24f = { 81 20 [2] a5 2e [2] 8e 02 [2] a0 20 [2] b4 3b [2] bb 21 [2] a5 3c [2] a7 3d [2] bc 3b [2] a0 3c [2] bc 13 }

  condition:
    any of them
}