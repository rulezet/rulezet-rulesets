rule TTP_XOR_MULT_DOSStub_0f5f {
  strings:
    $key_0f5f = { 5b 37 [2] 2f 2f [2] 68 2d [2] 2f 3c [2] 61 30 [2] 6d 3a [2] 7a 31 [2] 61 7f [2] 5c }

  condition:
    any of them
}