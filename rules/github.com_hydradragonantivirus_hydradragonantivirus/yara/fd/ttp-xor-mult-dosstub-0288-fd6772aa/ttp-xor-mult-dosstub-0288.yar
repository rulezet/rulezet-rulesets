rule TTP_XOR_MULT_DOSStub_0288 {
  strings:
    $key_0288 = { 56 e0 [2] 22 f8 [2] 65 fa [2] 22 eb [2] 6c e7 [2] 60 ed [2] 77 e6 [2] 6c a8 [2] 51 }

  condition:
    any of them
}