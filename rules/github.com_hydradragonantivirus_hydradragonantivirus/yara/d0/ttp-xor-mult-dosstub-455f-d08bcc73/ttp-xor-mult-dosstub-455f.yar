rule TTP_XOR_MULT_DOSStub_455f {
  strings:
    $key_455f = { 11 37 [2] 65 2f [2] 22 2d [2] 65 3c [2] 2b 30 [2] 27 3a [2] 30 31 [2] 2b 7f [2] 16 }

  condition:
    any of them
}