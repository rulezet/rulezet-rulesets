rule TTP_XOR_MULT_DOSStub_556f {
  strings:
    $key_556f = { 01 07 [2] 75 1f [2] 32 1d [2] 75 0c [2] 3b 00 [2] 37 0a [2] 20 01 [2] 3b 4f [2] 06 }

  condition:
    any of them
}