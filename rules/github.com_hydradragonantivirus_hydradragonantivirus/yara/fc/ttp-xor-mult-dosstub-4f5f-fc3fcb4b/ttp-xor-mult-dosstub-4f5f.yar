rule TTP_XOR_MULT_DOSStub_4f5f {
  strings:
    $key_4f5f = { 1b 37 [2] 6f 2f [2] 28 2d [2] 6f 3c [2] 21 30 [2] 2d 3a [2] 3a 31 [2] 21 7f [2] 1c }

  condition:
    any of them
}