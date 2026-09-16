rule TTP_XOR_QUAD_CurrentVersionRun_fe92 {
  strings:
    $key_fe92 = { ad fd [2] 89 f3 [2] a2 df [2] 8c fd [2] 98 e6 [2] 97 fc [2] 89 e1 [2] 8b e0 [2] 90 e6 [2] 8c e1 [2] 90 ce }

  condition:
    any of them
}