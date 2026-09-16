rule TTP_XOR_MULT_DOSStub_ec28 {
  strings:
    $key_ec28 = { b8 40 [2] cc 58 [2] 8b 5a [2] cc 4b [2] 82 47 [2] 8e 4d [2] 99 46 [2] 82 08 [2] bf }

  condition:
    any of them
}