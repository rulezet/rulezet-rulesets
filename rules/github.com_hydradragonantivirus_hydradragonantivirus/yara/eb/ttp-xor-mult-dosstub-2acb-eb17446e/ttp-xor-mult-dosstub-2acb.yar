rule TTP_XOR_MULT_DOSStub_2acb {
  strings:
    $key_2acb = { 7e a3 [2] 0a bb [2] 4d b9 [2] 0a a8 [2] 44 a4 [2] 48 ae [2] 5f a5 [2] 44 eb [2] 79 }

  condition:
    any of them
}