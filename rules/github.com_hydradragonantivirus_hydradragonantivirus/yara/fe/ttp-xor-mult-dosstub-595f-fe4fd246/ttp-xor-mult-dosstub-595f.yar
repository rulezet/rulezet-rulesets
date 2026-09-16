rule TTP_XOR_MULT_DOSStub_595f {
  strings:
    $key_595f = { 0d 37 [2] 79 2f [2] 3e 2d [2] 79 3c [2] 37 30 [2] 3b 3a [2] 2c 31 [2] 37 7f [2] 0a }

  condition:
    any of them
}