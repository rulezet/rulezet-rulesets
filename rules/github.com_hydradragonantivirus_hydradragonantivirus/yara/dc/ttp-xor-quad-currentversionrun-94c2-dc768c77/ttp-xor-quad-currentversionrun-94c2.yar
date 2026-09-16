rule TTP_XOR_QUAD_CurrentVersionRun_94c2 {
  strings:
    $key_94c2 = { c7 ad [2] e3 a3 [2] c8 8f [2] e6 ad [2] f2 b6 [2] fd ac [2] e3 b1 [2] e1 b0 [2] fa b6 [2] e6 b1 [2] fa 9e }

  condition:
    any of them
}