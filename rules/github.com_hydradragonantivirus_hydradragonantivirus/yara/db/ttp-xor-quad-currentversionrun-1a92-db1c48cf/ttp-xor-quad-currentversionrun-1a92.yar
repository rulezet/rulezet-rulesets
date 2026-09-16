rule TTP_XOR_QUAD_CurrentVersionRun_1a92 {
  strings:
    $key_1a92 = { 49 fd [2] 6d f3 [2] 46 df [2] 68 fd [2] 7c e6 [2] 73 fc [2] 6d e1 [2] 6f e0 [2] 74 e6 [2] 68 e1 [2] 74 ce }

  condition:
    any of them
}