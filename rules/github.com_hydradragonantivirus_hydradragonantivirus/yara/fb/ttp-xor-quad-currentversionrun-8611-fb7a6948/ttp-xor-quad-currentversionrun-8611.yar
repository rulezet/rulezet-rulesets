rule TTP_XOR_QUAD_CurrentVersionRun_8611 {
  strings:
    $key_8611 = { d5 7e [2] f1 70 [2] da 5c [2] f4 7e [2] e0 65 [2] ef 7f [2] f1 62 [2] f3 63 [2] e8 65 [2] f4 62 [2] e8 4d }

  condition:
    any of them
}