rule TTP_XOR_QUAD_CurrentVersionRun_2092 {
  strings:
    $key_2092 = { 73 fd [2] 57 f3 [2] 7c df [2] 52 fd [2] 46 e6 [2] 49 fc [2] 57 e1 [2] 55 e0 [2] 4e e6 [2] 52 e1 [2] 4e ce }

  condition:
    any of them
}