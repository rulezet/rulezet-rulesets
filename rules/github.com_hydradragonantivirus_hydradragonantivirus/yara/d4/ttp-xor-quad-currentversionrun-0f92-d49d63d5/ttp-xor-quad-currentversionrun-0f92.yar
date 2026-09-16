rule TTP_XOR_QUAD_CurrentVersionRun_0f92 {
  strings:
    $key_0f92 = { 5c fd [2] 78 f3 [2] 53 df [2] 7d fd [2] 69 e6 [2] 66 fc [2] 78 e1 [2] 7a e0 [2] 61 e6 [2] 7d e1 [2] 61 ce }

  condition:
    any of them
}