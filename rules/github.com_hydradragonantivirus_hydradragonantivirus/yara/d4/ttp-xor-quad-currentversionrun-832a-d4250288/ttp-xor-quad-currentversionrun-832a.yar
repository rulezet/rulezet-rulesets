rule TTP_XOR_QUAD_CurrentVersionRun_832a {
  strings:
    $key_832a = { d0 45 [2] f4 4b [2] df 67 [2] f1 45 [2] e5 5e [2] ea 44 [2] f4 59 [2] f6 58 [2] ed 5e [2] f1 59 [2] ed 76 }

  condition:
    any of them
}