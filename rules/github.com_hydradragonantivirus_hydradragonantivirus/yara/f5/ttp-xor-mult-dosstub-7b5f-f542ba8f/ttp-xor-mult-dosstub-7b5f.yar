rule TTP_XOR_MULT_DOSStub_7b5f {
  strings:
    $key_7b5f = { 2f 37 [2] 5b 2f [2] 1c 2d [2] 5b 3c [2] 15 30 [2] 19 3a [2] 0e 31 [2] 15 7f [2] 28 }

  condition:
    any of them
}