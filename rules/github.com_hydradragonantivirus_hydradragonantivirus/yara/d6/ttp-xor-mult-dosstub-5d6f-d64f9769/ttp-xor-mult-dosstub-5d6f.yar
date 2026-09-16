rule TTP_XOR_MULT_DOSStub_5d6f {
  strings:
    $key_5d6f = { 09 07 [2] 7d 1f [2] 3a 1d [2] 7d 0c [2] 33 00 [2] 3f 0a [2] 28 01 [2] 33 4f [2] 0e }

  condition:
    any of them
}