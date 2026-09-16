rule TTP_XOR_QUAD_CurrentVersionRun_0d92 {
  strings:
    $key_0d92 = { 5e fd [2] 7a f3 [2] 51 df [2] 7f fd [2] 6b e6 [2] 64 fc [2] 7a e1 [2] 78 e0 [2] 63 e6 [2] 7f e1 [2] 63 ce }

  condition:
    any of them
}