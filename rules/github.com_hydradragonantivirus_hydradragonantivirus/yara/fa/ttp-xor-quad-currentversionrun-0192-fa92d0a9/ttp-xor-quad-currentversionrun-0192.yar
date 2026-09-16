rule TTP_XOR_QUAD_CurrentVersionRun_0192 {
  strings:
    $key_0192 = { 52 fd [2] 76 f3 [2] 5d df [2] 73 fd [2] 67 e6 [2] 68 fc [2] 76 e1 [2] 74 e0 [2] 6f e6 [2] 73 e1 [2] 6f ce }

  condition:
    any of them
}