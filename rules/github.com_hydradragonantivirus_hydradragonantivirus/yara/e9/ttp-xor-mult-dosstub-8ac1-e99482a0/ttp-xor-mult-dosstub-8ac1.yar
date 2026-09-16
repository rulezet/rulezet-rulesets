rule TTP_XOR_MULT_DOSStub_8ac1 {
  strings:
    $key_8ac1 = { de a9 [2] aa b1 [2] ed b3 [2] aa a2 [2] e4 ae [2] e8 a4 [2] ff af [2] e4 e1 [2] d9 }

  condition:
    any of them
}