rule TTP_XOR_QUAD_CurrentVersionRun_ec92 {
  strings:
    $key_ec92 = { bf fd [2] 9b f3 [2] b0 df [2] 9e fd [2] 8a e6 [2] 85 fc [2] 9b e1 [2] 99 e0 [2] 82 e6 [2] 9e e1 [2] 82 ce }

  condition:
    any of them
}