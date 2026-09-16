rule TTP_XOR_QUAD_CurrentVersionRun_f392 {
  strings:
    $key_f392 = { a0 fd [2] 84 f3 [2] af df [2] 81 fd [2] 95 e6 [2] 9a fc [2] 84 e1 [2] 86 e0 [2] 9d e6 [2] 81 e1 [2] 9d ce }

  condition:
    any of them
}