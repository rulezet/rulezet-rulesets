rule TTP_XOR_QUAD_CurrentVersionRun_810b {
  strings:
    $key_810b = { d2 64 [2] f6 6a [2] dd 46 [2] f3 64 [2] e7 7f [2] e8 65 [2] f6 78 [2] f4 79 [2] ef 7f [2] f3 78 [2] ef 57 }

  condition:
    any of them
}