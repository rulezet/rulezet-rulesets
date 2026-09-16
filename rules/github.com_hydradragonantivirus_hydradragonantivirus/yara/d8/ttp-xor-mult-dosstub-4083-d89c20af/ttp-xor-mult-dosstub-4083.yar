rule TTP_XOR_MULT_DOSStub_4083 {
  strings:
    $key_4083 = { 14 eb [2] 60 f3 [2] 27 f1 [2] 60 e0 [2] 2e ec [2] 22 e6 [2] 35 ed [2] 2e a3 [2] 13 }

  condition:
    any of them
}