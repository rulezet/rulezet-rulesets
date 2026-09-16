rule TTP_XOR_QUAD_CurrentVersionRun_811b {
  strings:
    $key_811b = { d2 74 [2] f6 7a [2] dd 56 [2] f3 74 [2] e7 6f [2] e8 75 [2] f6 68 [2] f4 69 [2] ef 6f [2] f3 68 [2] ef 47 }

  condition:
    any of them
}