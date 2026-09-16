rule TTP_XOR_MULT_DOSStub_5acb {
  strings:
    $key_5acb = { 0e a3 [2] 7a bb [2] 3d b9 [2] 7a a8 [2] 34 a4 [2] 38 ae [2] 2f a5 [2] 34 eb [2] 09 }

  condition:
    any of them
}