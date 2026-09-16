rule TTP_XOR_MULT_DOSStub_91f7 {
  strings:
    $key_91f7 = { c5 9f [2] b1 87 [2] f6 85 [2] b1 94 [2] ff 98 [2] f3 92 [2] e4 99 [2] ff d7 [2] c2 }

  condition:
    any of them
}