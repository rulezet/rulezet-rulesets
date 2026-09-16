rule TTP_XOR_QUAD_CurrentVersionRun_d23f {
  strings:
    $key_d23f = { 81 50 [2] a5 5e [2] 8e 72 [2] a0 50 [2] b4 4b [2] bb 51 [2] a5 4c [2] a7 4d [2] bc 4b [2] a0 4c [2] bc 63 }

  condition:
    any of them
}