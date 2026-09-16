rule TTP_XOR_MULT_DOSStub_fdd4 {
  strings:
    $key_fdd4 = { a9 bc [2] dd a4 [2] 9a a6 [2] dd b7 [2] 93 bb [2] 9f b1 [2] 88 ba [2] 93 f4 [2] ae }

  condition:
    any of them
}