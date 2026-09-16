rule TTP_XOR_MULT_DOSStub_4a6f {
  strings:
    $key_4a6f = { 1e 07 [2] 6a 1f [2] 2d 1d [2] 6a 0c [2] 24 00 [2] 28 0a [2] 3f 01 [2] 24 4f [2] 19 }

  condition:
    any of them
}