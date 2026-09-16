rule TTP_XOR_QUAD_CurrentVersionRun_3992 {
  strings:
    $key_3992 = { 6a fd [2] 4e f3 [2] 65 df [2] 4b fd [2] 5f e6 [2] 50 fc [2] 4e e1 [2] 4c e0 [2] 57 e6 [2] 4b e1 [2] 57 ce }

  condition:
    any of them
}