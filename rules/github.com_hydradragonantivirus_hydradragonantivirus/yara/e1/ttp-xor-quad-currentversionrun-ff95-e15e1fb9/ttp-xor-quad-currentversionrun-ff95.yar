rule TTP_XOR_QUAD_CurrentVersionRun_ff95 {
  strings:
    $key_ff95 = { ac fa [2] 88 f4 [2] a3 d8 [2] 8d fa [2] 99 e1 [2] 96 fb [2] 88 e6 [2] 8a e7 [2] 91 e1 [2] 8d e6 [2] 91 c9 }

  condition:
    any of them
}