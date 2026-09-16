rule TTP_XOR_MULT_DOSStub_c699 {
  strings:
    $key_c699 = { 92 f1 [2] e6 e9 [2] a1 eb [2] e6 fa [2] a8 f6 [2] a4 fc [2] b3 f7 [2] a8 b9 [2] 95 }

  condition:
    any of them
}