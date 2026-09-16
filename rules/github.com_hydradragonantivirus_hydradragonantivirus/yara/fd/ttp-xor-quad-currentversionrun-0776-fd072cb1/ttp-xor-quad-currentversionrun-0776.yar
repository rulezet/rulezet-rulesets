rule TTP_XOR_QUAD_CurrentVersionRun_0776 {
  strings:
    $key_0776 = { 54 19 [2] 70 17 [2] 5b 3b [2] 75 19 [2] 61 02 [2] 6e 18 [2] 70 05 [2] 72 04 [2] 69 02 [2] 75 05 [2] 69 2a }

  condition:
    any of them
}