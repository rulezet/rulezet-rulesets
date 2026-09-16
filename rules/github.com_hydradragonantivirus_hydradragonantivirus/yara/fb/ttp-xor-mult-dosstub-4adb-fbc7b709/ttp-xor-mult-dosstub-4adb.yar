rule TTP_XOR_MULT_DOSStub_4adb {
  strings:
    $key_4adb = { 1e b3 [2] 6a ab [2] 2d a9 [2] 6a b8 [2] 24 b4 [2] 28 be [2] 3f b5 [2] 24 fb [2] 19 }

  condition:
    any of them
}