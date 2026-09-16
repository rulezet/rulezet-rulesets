rule TTP_XOR_MULT_DOSStub_4c5f {
  strings:
    $key_4c5f = { 18 37 [2] 6c 2f [2] 2b 2d [2] 6c 3c [2] 22 30 [2] 2e 3a [2] 39 31 [2] 22 7f [2] 1f }

  condition:
    any of them
}