rule TTP_XOR_QUAD_CurrentVersionRun_d56e {
  strings:
    $key_d56e = { 86 01 [2] a2 0f [2] 89 23 [2] a7 01 [2] b3 1a [2] bc 00 [2] a2 1d [2] a0 1c [2] bb 1a [2] a7 1d [2] bb 32 }

  condition:
    any of them
}