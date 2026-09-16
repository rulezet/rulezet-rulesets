rule TTP_XOR_QUAD_CurrentVersionRun_d2e3 {
  strings:
    $key_d2e3 = { 81 8c [2] a5 82 [2] 8e ae [2] a0 8c [2] b4 97 [2] bb 8d [2] a5 90 [2] a7 91 [2] bc 97 [2] a0 90 [2] bc bf }

  condition:
    any of them
}