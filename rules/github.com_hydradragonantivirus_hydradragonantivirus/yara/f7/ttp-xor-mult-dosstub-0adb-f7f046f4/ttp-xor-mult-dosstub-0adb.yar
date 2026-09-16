rule TTP_XOR_MULT_DOSStub_0adb {
  strings:
    $key_0adb = { 5e b3 [2] 2a ab [2] 6d a9 [2] 2a b8 [2] 64 b4 [2] 68 be [2] 7f b5 [2] 64 fb [2] 59 }

  condition:
    any of them
}