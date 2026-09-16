rule TTP_XOR_MULT_DOSStub_fed7 {
  strings:
    $key_fed7 = { aa bf [2] de a7 [2] 99 a5 [2] de b4 [2] 90 b8 [2] 9c b2 [2] 8b b9 [2] 90 f7 [2] ad }

  condition:
    any of them
}