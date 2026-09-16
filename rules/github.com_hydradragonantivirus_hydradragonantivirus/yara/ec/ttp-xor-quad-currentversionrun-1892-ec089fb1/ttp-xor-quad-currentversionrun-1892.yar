rule TTP_XOR_QUAD_CurrentVersionRun_1892 {
  strings:
    $key_1892 = { 4b fd [2] 6f f3 [2] 44 df [2] 6a fd [2] 7e e6 [2] 71 fc [2] 6f e1 [2] 6d e0 [2] 76 e6 [2] 6a e1 [2] 76 ce }

  condition:
    any of them
}