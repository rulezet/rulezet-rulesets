rule TTP_XOR_QUAD_CurrentVersionRun_1992 {
  strings:
    $key_1992 = { 4a fd [2] 6e f3 [2] 45 df [2] 6b fd [2] 7f e6 [2] 70 fc [2] 6e e1 [2] 6c e0 [2] 77 e6 [2] 6b e1 [2] 77 ce }

  condition:
    any of them
}