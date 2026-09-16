rule TTP_XOR_MULT_DOSStub_eac1 {
  strings:
    $key_eac1 = { be a9 [2] ca b1 [2] 8d b3 [2] ca a2 [2] 84 ae [2] 88 a4 [2] 9f af [2] 84 e1 [2] b9 }

  condition:
    any of them
}