rule TTP_XOR_QUAD_CurrentVersionRun_9a2f {
  strings:
    $key_9a2f = { c9 40 [2] ed 4e [2] c6 62 [2] e8 40 [2] fc 5b [2] f3 41 [2] ed 5c [2] ef 5d [2] f4 5b [2] e8 5c [2] f4 73 }

  condition:
    any of them
}