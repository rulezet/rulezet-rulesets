rule TTP_XOR_QUAD_CurrentVersionRun_81ff {
  strings:
    $key_81ff = { d2 90 [2] f6 9e [2] dd b2 [2] f3 90 [2] e7 8b [2] e8 91 [2] f6 8c [2] f4 8d [2] ef 8b [2] f3 8c [2] ef a3 }

  condition:
    any of them
}