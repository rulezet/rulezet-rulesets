rule TTP_XOR_MULT_DOSStub_2399 {
  strings:
    $key_2399 = { 77 f1 [2] 03 e9 [2] 44 eb [2] 03 fa [2] 4d f6 [2] 41 fc [2] 56 f7 [2] 4d b9 [2] 70 }

  condition:
    any of them
}