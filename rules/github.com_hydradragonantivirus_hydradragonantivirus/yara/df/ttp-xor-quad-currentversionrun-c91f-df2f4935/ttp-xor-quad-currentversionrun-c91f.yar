rule TTP_XOR_QUAD_CurrentVersionRun_c91f {
  strings:
    $key_c91f = { 9a 70 [2] be 7e [2] 95 52 [2] bb 70 [2] af 6b [2] a0 71 [2] be 6c [2] bc 6d [2] a7 6b [2] bb 6c [2] a7 43 }

  condition:
    any of them
}