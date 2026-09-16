rule TTP_XOR_MULT_DOSStub_3bd8 {
  strings:
    $key_3bd8 = { 6f b0 [2] 1b a8 [2] 5c aa [2] 1b bb [2] 55 b7 [2] 59 bd [2] 4e b6 [2] 55 f8 [2] 68 }

  condition:
    any of them
}