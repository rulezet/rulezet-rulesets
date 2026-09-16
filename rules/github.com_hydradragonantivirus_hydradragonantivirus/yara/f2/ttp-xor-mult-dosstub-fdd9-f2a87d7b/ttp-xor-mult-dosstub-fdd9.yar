rule TTP_XOR_MULT_DOSStub_fdd9 {
  strings:
    $key_fdd9 = { a9 b1 [2] dd a9 [2] 9a ab [2] dd ba [2] 93 b6 [2] 9f bc [2] 88 b7 [2] 93 f9 [2] ae }

  condition:
    any of them
}