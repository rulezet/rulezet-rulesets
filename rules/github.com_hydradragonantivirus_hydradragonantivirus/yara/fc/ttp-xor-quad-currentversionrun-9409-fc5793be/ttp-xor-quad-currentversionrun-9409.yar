rule TTP_XOR_QUAD_CurrentVersionRun_9409 {
  strings:
    $key_9409 = { c7 66 [2] e3 68 [2] c8 44 [2] e6 66 [2] f2 7d [2] fd 67 [2] e3 7a [2] e1 7b [2] fa 7d [2] e6 7a [2] fa 55 }

  condition:
    any of them
}