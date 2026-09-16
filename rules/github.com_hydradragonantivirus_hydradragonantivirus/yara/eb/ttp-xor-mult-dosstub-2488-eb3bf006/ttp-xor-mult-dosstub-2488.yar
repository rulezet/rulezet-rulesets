rule TTP_XOR_MULT_DOSStub_2488 {
  strings:
    $key_2488 = { 70 e0 [2] 04 f8 [2] 43 fa [2] 04 eb [2] 4a e7 [2] 46 ed [2] 51 e6 [2] 4a a8 [2] 77 }

  condition:
    any of them
}