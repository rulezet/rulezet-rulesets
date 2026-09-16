rule TTP_XOR_MULT_DOSStub_bcc0 {
  strings:
    $key_bcc0 = { e8 a8 [2] 9c b0 [2] db b2 [2] 9c a3 [2] d2 af [2] de a5 [2] c9 ae [2] d2 e0 [2] ef }

  condition:
    any of them
}