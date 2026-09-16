rule TTP_XOR_MULT_DOSStub_fdd8 {
  strings:
    $key_fdd8 = { a9 b0 [2] dd a8 [2] 9a aa [2] dd bb [2] 93 b7 [2] 9f bd [2] 88 b6 [2] 93 f8 [2] ae }

  condition:
    any of them
}