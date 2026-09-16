rule TTP_XOR_QUAD_CurrentVersionRun_7d92 {
  strings:
    $key_7d92 = { 2e fd [2] 0a f3 [2] 21 df [2] 0f fd [2] 1b e6 [2] 14 fc [2] 0a e1 [2] 08 e0 [2] 13 e6 [2] 0f e1 [2] 13 ce }

  condition:
    any of them
}