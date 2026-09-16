rule TTP_XOR_QUAD_CurrentVersionRun_9488 {
  strings:
    $key_9488 = { c7 e7 [2] e3 e9 [2] c8 c5 [2] e6 e7 [2] f2 fc [2] fd e6 [2] e3 fb [2] e1 fa [2] fa fc [2] e6 fb [2] fa d4 }

  condition:
    any of them
}