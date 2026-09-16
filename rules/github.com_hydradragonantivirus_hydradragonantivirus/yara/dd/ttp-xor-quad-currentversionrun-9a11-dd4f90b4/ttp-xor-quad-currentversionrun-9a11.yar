rule TTP_XOR_QUAD_CurrentVersionRun_9a11 {
  strings:
    $key_9a11 = { c9 7e [2] ed 70 [2] c6 5c [2] e8 7e [2] fc 65 [2] f3 7f [2] ed 62 [2] ef 63 [2] f4 65 [2] e8 62 [2] f4 4d }

  condition:
    any of them
}