rule TTP_XOR_QUAD_CurrentVersionRun_0e92 {
  strings:
    $key_0e92 = { 5d fd [2] 79 f3 [2] 52 df [2] 7c fd [2] 68 e6 [2] 67 fc [2] 79 e1 [2] 7b e0 [2] 60 e6 [2] 7c e1 [2] 60 ce }

  condition:
    any of them
}