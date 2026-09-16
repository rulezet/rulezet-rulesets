rule TTP_XOR_MULT_DOSStub_171c {
  strings:
    $key_171c = { 43 74 [2] 37 6c [2] 70 6e [2] 37 7f [2] 79 73 [2] 75 79 [2] 62 72 [2] 79 3c [2] 44 }

  condition:
    any of them
}