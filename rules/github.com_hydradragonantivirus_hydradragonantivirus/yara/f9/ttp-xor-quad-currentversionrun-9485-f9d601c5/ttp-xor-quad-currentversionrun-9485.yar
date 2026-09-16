rule TTP_XOR_QUAD_CurrentVersionRun_9485 {
  strings:
    $key_9485 = { c7 ea [2] e3 e4 [2] c8 c8 [2] e6 ea [2] f2 f1 [2] fd eb [2] e3 f6 [2] e1 f7 [2] fa f1 [2] e6 f6 [2] fa d9 }

  condition:
    any of them
}