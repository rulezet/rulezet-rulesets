rule TTP_XOR_QUAD_CurrentVersionRun_8a88 {
  strings:
    $key_8a88 = { d9 e7 [2] fd e9 [2] d6 c5 [2] f8 e7 [2] ec fc [2] e3 e6 [2] fd fb [2] ff fa [2] e4 fc [2] f8 fb [2] e4 d4 }

  condition:
    any of them
}