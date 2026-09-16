rule TTP_XOR_QUAD_CurrentVersionRun_81ef {
  strings:
    $key_81ef = { d2 80 [2] f6 8e [2] dd a2 [2] f3 80 [2] e7 9b [2] e8 81 [2] f6 9c [2] f4 9d [2] ef 9b [2] f3 9c [2] ef b3 }

  condition:
    any of them
}