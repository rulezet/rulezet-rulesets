rule TTP_XOR_MULT_DOSStub_218b {
  strings:
    $key_218b = { 75 e3 [2] 01 fb [2] 46 f9 [2] 01 e8 [2] 4f e4 [2] 43 ee [2] 54 e5 [2] 4f ab [2] 72 }

  condition:
    any of them
}