rule TTP_XOR_QUAD_CurrentVersionRun_cee3 {
  strings:
    $key_cee3 = { 9d 8c [2] b9 82 [2] 92 ae [2] bc 8c [2] a8 97 [2] a7 8d [2] b9 90 [2] bb 91 [2] a0 97 [2] bc 90 [2] a0 bf }

  condition:
    any of them
}