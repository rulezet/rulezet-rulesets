rule TTP_XOR_MULT_DOSStub_1adb {
  strings:
    $key_1adb = { 4e b3 [2] 3a ab [2] 7d a9 [2] 3a b8 [2] 74 b4 [2] 78 be [2] 6f b5 [2] 74 fb [2] 49 }

  condition:
    any of them
}