rule TTP_XOR_MULT_DOSStub_fdbe {
  strings:
    $key_fdbe = { a9 d6 [2] dd ce [2] 9a cc [2] dd dd [2] 93 d1 [2] 9f db [2] 88 d0 [2] 93 9e [2] ae }

  condition:
    any of them
}