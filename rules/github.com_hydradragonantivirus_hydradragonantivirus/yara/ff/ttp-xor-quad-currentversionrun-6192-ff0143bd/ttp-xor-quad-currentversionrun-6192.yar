rule TTP_XOR_QUAD_CurrentVersionRun_6192 {
  strings:
    $key_6192 = { 32 fd [2] 16 f3 [2] 3d df [2] 13 fd [2] 07 e6 [2] 08 fc [2] 16 e1 [2] 14 e0 [2] 0f e6 [2] 13 e1 [2] 0f ce }

  condition:
    any of them
}