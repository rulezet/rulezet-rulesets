rule TTP_XOR_MULT_DOSStub_ba94 {
  strings:
    $key_ba94 = { ee fc [2] 9a e4 [2] dd e6 [2] 9a f7 [2] d4 fb [2] d8 f1 [2] cf fa [2] d4 b4 [2] e9 }

  condition:
    any of them
}