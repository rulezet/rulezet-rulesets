rule TTP_XOR_QUAD_CurrentVersionRun_6e92 {
  strings:
    $key_6e92 = { 3d fd [2] 19 f3 [2] 32 df [2] 1c fd [2] 08 e6 [2] 07 fc [2] 19 e1 [2] 1b e0 [2] 00 e6 [2] 1c e1 [2] 00 ce }

  condition:
    any of them
}