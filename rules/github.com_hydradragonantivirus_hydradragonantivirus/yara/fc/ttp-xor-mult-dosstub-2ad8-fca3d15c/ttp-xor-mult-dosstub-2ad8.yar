rule TTP_XOR_MULT_DOSStub_2ad8 {
  strings:
    $key_2ad8 = { 7e b0 [2] 0a a8 [2] 4d aa [2] 0a bb [2] 44 b7 [2] 48 bd [2] 5f b6 [2] 44 f8 [2] 79 }

  condition:
    any of them
}