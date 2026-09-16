rule TTP_XOR_QUAD_CurrentVersionRun_9aff {
  strings:
    $key_9aff = { c9 90 [2] ed 9e [2] c6 b2 [2] e8 90 [2] fc 8b [2] f3 91 [2] ed 8c [2] ef 8d [2] f4 8b [2] e8 8c [2] f4 a3 }

  condition:
    any of them
}