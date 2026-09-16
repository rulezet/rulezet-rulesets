rule TTP_XOR_QUAD_CurrentVersionRun_f4b1 {
  strings:
    $key_f4b1 = { a7 de [2] 83 d0 [2] a8 fc [2] 86 de [2] 92 c5 [2] 9d df [2] 83 c2 [2] 81 c3 [2] 9a c5 [2] 86 c2 [2] 9a ed }

  condition:
    any of them
}