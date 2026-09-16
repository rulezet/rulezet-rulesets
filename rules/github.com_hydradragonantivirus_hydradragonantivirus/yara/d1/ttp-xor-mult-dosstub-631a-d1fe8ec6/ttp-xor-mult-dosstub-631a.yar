rule TTP_XOR_MULT_DOSStub_631a {
  strings:
    $key_631a = { 37 72 [2] 43 6a [2] 04 68 [2] 43 79 [2] 0d 75 [2] 01 7f [2] 16 74 [2] 0d 3a [2] 30 }

  condition:
    any of them
}