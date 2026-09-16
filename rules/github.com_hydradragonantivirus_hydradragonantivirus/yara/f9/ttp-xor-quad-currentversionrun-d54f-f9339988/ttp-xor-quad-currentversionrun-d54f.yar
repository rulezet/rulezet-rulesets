rule TTP_XOR_QUAD_CurrentVersionRun_d54f {
  strings:
    $key_d54f = { 86 20 [2] a2 2e [2] 89 02 [2] a7 20 [2] b3 3b [2] bc 21 [2] a2 3c [2] a0 3d [2] bb 3b [2] a7 3c [2] bb 13 }

  condition:
    any of them
}