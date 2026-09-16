rule TTP_XOR_QUAD_CurrentVersionRun_9478 {
  strings:
    $key_9478 = { c7 17 [2] e3 19 [2] c8 35 [2] e6 17 [2] f2 0c [2] fd 16 [2] e3 0b [2] e1 0a [2] fa 0c [2] e6 0b [2] fa 24 }

  condition:
    any of them
}