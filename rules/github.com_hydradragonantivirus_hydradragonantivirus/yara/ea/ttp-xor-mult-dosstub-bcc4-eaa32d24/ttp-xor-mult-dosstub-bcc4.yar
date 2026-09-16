rule TTP_XOR_MULT_DOSStub_bcc4 {
  strings:
    $key_bcc4 = { e8 ac [2] 9c b4 [2] db b6 [2] 9c a7 [2] d2 ab [2] de a1 [2] c9 aa [2] d2 e4 [2] ef }

  condition:
    any of them
}