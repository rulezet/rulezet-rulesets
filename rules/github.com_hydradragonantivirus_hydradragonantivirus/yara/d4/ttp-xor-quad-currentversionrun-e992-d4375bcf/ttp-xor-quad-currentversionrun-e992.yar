rule TTP_XOR_QUAD_CurrentVersionRun_e992 {
  strings:
    $key_e992 = { ba fd [2] 9e f3 [2] b5 df [2] 9b fd [2] 8f e6 [2] 80 fc [2] 9e e1 [2] 9c e0 [2] 87 e6 [2] 9b e1 [2] 87 ce }

  condition:
    any of them
}