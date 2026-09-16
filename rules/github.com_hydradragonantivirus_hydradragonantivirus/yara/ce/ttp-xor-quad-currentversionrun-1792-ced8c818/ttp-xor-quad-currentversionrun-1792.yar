rule TTP_XOR_QUAD_CurrentVersionRun_1792 {
  strings:
    $key_1792 = { 44 fd [2] 60 f3 [2] 4b df [2] 65 fd [2] 71 e6 [2] 7e fc [2] 60 e1 [2] 62 e0 [2] 79 e6 [2] 65 e1 [2] 79 ce }

  condition:
    any of them
}