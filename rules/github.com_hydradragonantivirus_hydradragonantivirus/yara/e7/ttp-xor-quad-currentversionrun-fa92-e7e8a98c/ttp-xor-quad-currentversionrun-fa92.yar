rule TTP_XOR_QUAD_CurrentVersionRun_fa92 {
  strings:
    $key_fa92 = { a9 fd [2] 8d f3 [2] a6 df [2] 88 fd [2] 9c e6 [2] 93 fc [2] 8d e1 [2] 8f e0 [2] 94 e6 [2] 88 e1 [2] 94 ce }

  condition:
    any of them
}