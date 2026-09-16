rule TTP_XOR_QUAD_CurrentVersionRun_1092 {
  strings:
    $key_1092 = { 43 fd [2] 67 f3 [2] 4c df [2] 62 fd [2] 76 e6 [2] 79 fc [2] 67 e1 [2] 65 e0 [2] 7e e6 [2] 62 e1 [2] 7e ce }

  condition:
    any of them
}