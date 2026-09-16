rule TTP_XOR_MULT_DOSStub_5e94 {
  strings:
    $key_5e94 = { 0a fc [2] 7e e4 [2] 39 e6 [2] 7e f7 [2] 30 fb [2] 3c f1 [2] 2b fa [2] 30 b4 [2] 0d }

  condition:
    any of them
}