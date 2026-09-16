rule TTP_XOR_MULT_DOSStub_6208 {
  strings:
    $key_6208 = { 36 60 [2] 42 78 [2] 05 7a [2] 42 6b [2] 0c 67 [2] 00 6d [2] 17 66 [2] 0c 28 [2] 31 }

  condition:
    any of them
}