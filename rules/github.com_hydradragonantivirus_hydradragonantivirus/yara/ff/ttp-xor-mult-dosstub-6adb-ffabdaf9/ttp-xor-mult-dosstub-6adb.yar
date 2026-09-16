rule TTP_XOR_MULT_DOSStub_6adb {
  strings:
    $key_6adb = { 3e b3 [2] 4a ab [2] 0d a9 [2] 4a b8 [2] 04 b4 [2] 08 be [2] 1f b5 [2] 04 fb [2] 39 }

  condition:
    any of them
}