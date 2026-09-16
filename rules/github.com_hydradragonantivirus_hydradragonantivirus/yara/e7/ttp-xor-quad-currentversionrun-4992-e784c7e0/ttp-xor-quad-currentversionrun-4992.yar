rule TTP_XOR_QUAD_CurrentVersionRun_4992 {
  strings:
    $key_4992 = { 1a fd [2] 3e f3 [2] 15 df [2] 3b fd [2] 2f e6 [2] 20 fc [2] 3e e1 [2] 3c e0 [2] 27 e6 [2] 3b e1 [2] 27 ce }

  condition:
    any of them
}