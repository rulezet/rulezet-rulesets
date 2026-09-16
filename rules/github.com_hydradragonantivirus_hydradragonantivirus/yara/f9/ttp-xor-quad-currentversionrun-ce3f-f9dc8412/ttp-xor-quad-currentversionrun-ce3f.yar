rule TTP_XOR_QUAD_CurrentVersionRun_ce3f {
  strings:
    $key_ce3f = { 9d 50 [2] b9 5e [2] 92 72 [2] bc 50 [2] a8 4b [2] a7 51 [2] b9 4c [2] bb 4d [2] a0 4b [2] bc 4c [2] a0 63 }

  condition:
    any of them
}