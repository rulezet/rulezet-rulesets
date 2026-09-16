rule TTP_XOR_QUAD_CurrentVersionRun_57b1 {
  strings:
    $key_57b1 = { 04 de [2] 20 d0 [2] 0b fc [2] 25 de [2] 31 c5 [2] 3e df [2] 20 c2 [2] 22 c3 [2] 39 c5 [2] 25 c2 [2] 39 ed }

  condition:
    any of them
}