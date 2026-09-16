rule TTP_XOR_QUAD_CurrentVersionRun_c912 {
  strings:
    $key_c912 = { 9a 7d [2] be 73 [2] 95 5f [2] bb 7d [2] af 66 [2] a0 7c [2] be 61 [2] bc 60 [2] a7 66 [2] bb 61 [2] a7 4e }

  condition:
    any of them
}