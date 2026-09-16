rule TTP_XOR_QUAD_CurrentVersionRun_da92 {
  strings:
    $key_da92 = { 89 fd [2] ad f3 [2] 86 df [2] a8 fd [2] bc e6 [2] b3 fc [2] ad e1 [2] af e0 [2] b4 e6 [2] a8 e1 [2] b4 ce }

  condition:
    any of them
}