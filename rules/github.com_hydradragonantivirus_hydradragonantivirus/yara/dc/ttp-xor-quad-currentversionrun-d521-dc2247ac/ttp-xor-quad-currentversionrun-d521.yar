rule TTP_XOR_QUAD_CurrentVersionRun_d521 {
  strings:
    $key_d521 = { 86 4e [2] a2 40 [2] 89 6c [2] a7 4e [2] b3 55 [2] bc 4f [2] a2 52 [2] a0 53 [2] bb 55 [2] a7 52 [2] bb 7d }

  condition:
    any of them
}