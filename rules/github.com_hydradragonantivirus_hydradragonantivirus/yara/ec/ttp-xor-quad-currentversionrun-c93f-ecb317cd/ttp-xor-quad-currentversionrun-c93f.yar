rule TTP_XOR_QUAD_CurrentVersionRun_c93f {
  strings:
    $key_c93f = { 9a 50 [2] be 5e [2] 95 72 [2] bb 50 [2] af 4b [2] a0 51 [2] be 4c [2] bc 4d [2] a7 4b [2] bb 4c [2] a7 63 }

  condition:
    any of them
}