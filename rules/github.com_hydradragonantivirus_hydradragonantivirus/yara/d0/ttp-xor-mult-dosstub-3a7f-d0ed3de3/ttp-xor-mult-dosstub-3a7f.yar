rule TTP_XOR_MULT_DOSStub_3a7f {
  strings:
    $key_3a7f = { 6e 17 [2] 1a 0f [2] 5d 0d [2] 1a 1c [2] 54 10 [2] 58 1a [2] 4f 11 [2] 54 5f [2] 69 }

  condition:
    any of them
}