rule TTP_XOR_MULT_DOSStub_fdca {
  strings:
    $key_fdca = { a9 a2 [2] dd ba [2] 9a b8 [2] dd a9 [2] 93 a5 [2] 9f af [2] 88 a4 [2] 93 ea [2] ae }

  condition:
    any of them
}