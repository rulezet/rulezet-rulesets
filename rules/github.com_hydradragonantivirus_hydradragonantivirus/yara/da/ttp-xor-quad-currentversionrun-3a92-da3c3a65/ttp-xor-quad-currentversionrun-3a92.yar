rule TTP_XOR_QUAD_CurrentVersionRun_3a92 {
  strings:
    $key_3a92 = { 69 fd [2] 4d f3 [2] 66 df [2] 48 fd [2] 5c e6 [2] 53 fc [2] 4d e1 [2] 4f e0 [2] 54 e6 [2] 48 e1 [2] 54 ce }

  condition:
    any of them
}