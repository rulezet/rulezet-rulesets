rule TTP_XOR_QUAD_CurrentVersionRun_9a3c {
  strings:
    $key_9a3c = { c9 53 [2] ed 5d [2] c6 71 [2] e8 53 [2] fc 48 [2] f3 52 [2] ed 4f [2] ef 4e [2] f4 48 [2] e8 4f [2] f4 60 }

  condition:
    any of them
}