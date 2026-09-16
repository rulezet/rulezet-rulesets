rule TTP_XOR_QUAD_CurrentVersionRun_812b {
  strings:
    $key_812b = { d2 44 [2] f6 4a [2] dd 66 [2] f3 44 [2] e7 5f [2] e8 45 [2] f6 58 [2] f4 59 [2] ef 5f [2] f3 58 [2] ef 77 }

  condition:
    any of them
}