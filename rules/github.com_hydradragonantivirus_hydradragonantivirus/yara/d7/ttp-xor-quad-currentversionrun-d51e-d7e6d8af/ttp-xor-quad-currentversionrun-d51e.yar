rule TTP_XOR_QUAD_CurrentVersionRun_d51e {
  strings:
    $key_d51e = { 86 71 [2] a2 7f [2] 89 53 [2] a7 71 [2] b3 6a [2] bc 70 [2] a2 6d [2] a0 6c [2] bb 6a [2] a7 6d [2] bb 42 }

  condition:
    any of them
}