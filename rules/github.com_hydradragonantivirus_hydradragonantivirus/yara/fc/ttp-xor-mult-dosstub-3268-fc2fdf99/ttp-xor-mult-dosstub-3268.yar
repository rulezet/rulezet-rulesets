rule TTP_XOR_MULT_DOSStub_3268 {
  strings:
    $key_3268 = { 66 00 [2] 12 18 [2] 55 1a [2] 12 0b [2] 5c 07 [2] 50 0d [2] 47 06 [2] 5c 48 [2] 61 }

  condition:
    any of them
}