rule TTP_XOR_MULT_DOSStub_b0cd {
  strings:
    $key_b0cd = { e4 a5 [2] 90 bd [2] d7 bf [2] 90 ae [2] de a2 [2] d2 a8 [2] c5 a3 [2] de ed [2] e3 }

  condition:
    any of them
}