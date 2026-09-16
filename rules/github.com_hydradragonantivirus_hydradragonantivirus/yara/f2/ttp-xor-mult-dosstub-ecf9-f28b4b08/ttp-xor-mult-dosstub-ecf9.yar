rule TTP_XOR_MULT_DOSStub_ecf9 {
  strings:
    $key_ecf9 = { b8 91 [2] cc 89 [2] 8b 8b [2] cc 9a [2] 82 96 [2] 8e 9c [2] 99 97 [2] 82 d9 [2] bf }

  condition:
    any of them
}