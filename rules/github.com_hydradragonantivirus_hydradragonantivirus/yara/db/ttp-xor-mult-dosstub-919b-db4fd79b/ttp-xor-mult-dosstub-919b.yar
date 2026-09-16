rule TTP_XOR_MULT_DOSStub_919b {
  strings:
    $key_919b = { c5 f3 [2] b1 eb [2] f6 e9 [2] b1 f8 [2] ff f4 [2] f3 fe [2] e4 f5 [2] ff bb [2] c2 }

  condition:
    any of them
}