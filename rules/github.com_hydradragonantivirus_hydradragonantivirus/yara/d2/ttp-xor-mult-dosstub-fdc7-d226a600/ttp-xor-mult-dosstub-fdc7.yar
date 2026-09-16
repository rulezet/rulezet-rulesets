rule TTP_XOR_MULT_DOSStub_fdc7 {
  strings:
    $key_fdc7 = { a9 af [2] dd b7 [2] 9a b5 [2] dd a4 [2] 93 a8 [2] 9f a2 [2] 88 a9 [2] 93 e7 [2] ae }

  condition:
    any of them
}