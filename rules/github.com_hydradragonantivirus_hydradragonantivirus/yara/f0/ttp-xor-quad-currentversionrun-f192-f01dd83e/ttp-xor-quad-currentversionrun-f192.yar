rule TTP_XOR_QUAD_CurrentVersionRun_f192 {
  strings:
    $key_f192 = { a2 fd [2] 86 f3 [2] ad df [2] 83 fd [2] 97 e6 [2] 98 fc [2] 86 e1 [2] 84 e0 [2] 9f e6 [2] 83 e1 [2] 9f ce }

  condition:
    any of them
}