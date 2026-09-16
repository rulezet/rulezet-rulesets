rule TTP_XOR_QUAD_CurrentVersionRun_d792 {
  strings:
    $key_d792 = { 84 fd [2] a0 f3 [2] 8b df [2] a5 fd [2] b1 e6 [2] be fc [2] a0 e1 [2] a2 e0 [2] b9 e6 [2] a5 e1 [2] b9 ce }

  condition:
    any of them
}