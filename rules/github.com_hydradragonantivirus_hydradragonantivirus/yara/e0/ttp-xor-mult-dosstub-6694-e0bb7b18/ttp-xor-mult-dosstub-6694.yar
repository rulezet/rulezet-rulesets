rule TTP_XOR_MULT_DOSStub_6694 {
  strings:
    $key_6694 = { 32 fc [2] 46 e4 [2] 01 e6 [2] 46 f7 [2] 08 fb [2] 04 f1 [2] 13 fa [2] 08 b4 [2] 35 }

  condition:
    any of them
}