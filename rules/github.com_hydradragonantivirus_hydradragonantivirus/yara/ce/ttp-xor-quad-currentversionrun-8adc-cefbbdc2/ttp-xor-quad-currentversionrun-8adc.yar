rule TTP_XOR_QUAD_CurrentVersionRun_8adc {
  strings:
    $key_8adc = { d9 b3 [2] fd bd [2] d6 91 [2] f8 b3 [2] ec a8 [2] e3 b2 [2] fd af [2] ff ae [2] e4 a8 [2] f8 af [2] e4 80 }

  condition:
    any of them
}