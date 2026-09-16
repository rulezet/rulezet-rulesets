rule TTP_XOR_MULT_DOSStub_2588 {
  strings:
    $key_2588 = { 71 e0 [2] 05 f8 [2] 42 fa [2] 05 eb [2] 4b e7 [2] 47 ed [2] 50 e6 [2] 4b a8 [2] 76 }

  condition:
    any of them
}