rule TTP_XOR_QUAD_CurrentVersionRun_812a {
  strings:
    $key_812a = { d2 45 [2] f6 4b [2] dd 67 [2] f3 45 [2] e7 5e [2] e8 44 [2] f6 59 [2] f4 58 [2] ef 5e [2] f3 59 [2] ef 76 }

  condition:
    any of them
}