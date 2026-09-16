rule TTP_XOR_QUAD_CurrentVersionRun_ea92 {
  strings:
    $key_ea92 = { b9 fd [2] 9d f3 [2] b6 df [2] 98 fd [2] 8c e6 [2] 83 fc [2] 9d e1 [2] 9f e0 [2] 84 e6 [2] 98 e1 [2] 84 ce }

  condition:
    any of them
}