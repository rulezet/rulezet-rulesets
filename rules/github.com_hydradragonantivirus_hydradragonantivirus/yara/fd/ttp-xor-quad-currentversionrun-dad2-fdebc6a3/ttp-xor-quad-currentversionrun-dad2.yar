rule TTP_XOR_QUAD_CurrentVersionRun_dad2 {
  strings:
    $key_dad2 = { 89 bd [2] ad b3 [2] 86 9f [2] a8 bd [2] bc a6 [2] b3 bc [2] ad a1 [2] af a0 [2] b4 a6 [2] a8 a1 [2] b4 8e }

  condition:
    any of them
}