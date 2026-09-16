rule TTP_XOR_MULT_DOSStub_318b {
  strings:
    $key_318b = { 65 e3 [2] 11 fb [2] 56 f9 [2] 11 e8 [2] 5f e4 [2] 53 ee [2] 44 e5 [2] 5f ab [2] 62 }

  condition:
    any of them
}