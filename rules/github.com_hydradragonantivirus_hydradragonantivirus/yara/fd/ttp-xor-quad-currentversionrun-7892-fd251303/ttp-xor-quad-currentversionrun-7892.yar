rule TTP_XOR_QUAD_CurrentVersionRun_7892 {
  strings:
    $key_7892 = { 2b fd [2] 0f f3 [2] 24 df [2] 0a fd [2] 1e e6 [2] 11 fc [2] 0f e1 [2] 0d e0 [2] 16 e6 [2] 0a e1 [2] 16 ce }

  condition:
    any of them
}