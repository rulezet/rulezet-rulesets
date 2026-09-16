rule TTP_XOR_MULT_DOSStub_326f {
  strings:
    $key_326f = { 66 07 [2] 12 1f [2] 55 1d [2] 12 0c [2] 5c 00 [2] 50 0a [2] 47 01 [2] 5c 4f [2] 61 }

  condition:
    any of them
}