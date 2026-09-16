rule TTP_XOR_QUAD_CurrentVersionRun_e892 {
  strings:
    $key_e892 = { bb fd [2] 9f f3 [2] b4 df [2] 9a fd [2] 8e e6 [2] 81 fc [2] 9f e1 [2] 9d e0 [2] 86 e6 [2] 9a e1 [2] 86 ce }

  condition:
    any of them
}