rule TTP_XOR_MULT_DOSStub_1a6f {
  strings:
    $key_1a6f = { 4e 07 [2] 3a 1f [2] 7d 1d [2] 3a 0c [2] 74 00 [2] 78 0a [2] 6f 01 [2] 74 4f [2] 49 }

  condition:
    any of them
}