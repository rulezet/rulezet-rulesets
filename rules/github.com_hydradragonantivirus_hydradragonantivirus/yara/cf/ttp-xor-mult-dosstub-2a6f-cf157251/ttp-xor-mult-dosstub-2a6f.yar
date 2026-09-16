rule TTP_XOR_MULT_DOSStub_2a6f {
  strings:
    $key_2a6f = { 7e 07 [2] 0a 1f [2] 4d 1d [2] 0a 0c [2] 44 00 [2] 48 0a [2] 5f 01 [2] 44 4f [2] 79 }

  condition:
    any of them
}