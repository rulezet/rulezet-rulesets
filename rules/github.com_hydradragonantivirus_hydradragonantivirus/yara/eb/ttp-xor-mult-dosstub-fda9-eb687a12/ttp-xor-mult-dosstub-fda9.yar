rule TTP_XOR_MULT_DOSStub_fda9 {
  strings:
    $key_fda9 = { a9 c1 [2] dd d9 [2] 9a db [2] dd ca [2] 93 c6 [2] 9f cc [2] 88 c7 [2] 93 89 [2] ae }

  condition:
    any of them
}