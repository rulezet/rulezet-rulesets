rule TTP_XOR_QUAD_CurrentVersionRun_7192 {
  strings:
    $key_7192 = { 22 fd [2] 06 f3 [2] 2d df [2] 03 fd [2] 17 e6 [2] 18 fc [2] 06 e1 [2] 04 e0 [2] 1f e6 [2] 03 e1 [2] 1f ce }

  condition:
    any of them
}