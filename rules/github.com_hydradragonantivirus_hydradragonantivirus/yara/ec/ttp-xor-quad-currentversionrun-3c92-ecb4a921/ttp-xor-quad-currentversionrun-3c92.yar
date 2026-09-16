rule TTP_XOR_QUAD_CurrentVersionRun_3c92 {
  strings:
    $key_3c92 = { 6f fd [2] 4b f3 [2] 60 df [2] 4e fd [2] 5a e6 [2] 55 fc [2] 4b e1 [2] 49 e0 [2] 52 e6 [2] 4e e1 [2] 52 ce }

  condition:
    any of them
}