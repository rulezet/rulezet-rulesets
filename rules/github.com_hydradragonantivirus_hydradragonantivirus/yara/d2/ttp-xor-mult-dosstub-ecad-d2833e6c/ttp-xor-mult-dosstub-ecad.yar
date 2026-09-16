rule TTP_XOR_MULT_DOSStub_ecad {
  strings:
    $key_ecad = { b8 c5 [2] cc dd [2] 8b df [2] cc ce [2] 82 c2 [2] 8e c8 [2] 99 c3 [2] 82 8d [2] bf }

  condition:
    any of them
}