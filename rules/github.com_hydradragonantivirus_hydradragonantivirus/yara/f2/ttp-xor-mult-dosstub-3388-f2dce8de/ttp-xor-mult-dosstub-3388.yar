rule TTP_XOR_MULT_DOSStub_3388 {
  strings:
    $key_3388 = { 67 e0 [2] 13 f8 [2] 54 fa [2] 13 eb [2] 5d e7 [2] 51 ed [2] 46 e6 [2] 5d a8 [2] 60 }

  condition:
    any of them
}