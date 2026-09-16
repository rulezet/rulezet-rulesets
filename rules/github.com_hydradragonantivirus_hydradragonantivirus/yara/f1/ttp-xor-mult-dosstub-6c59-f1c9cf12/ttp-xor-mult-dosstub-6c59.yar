rule TTP_XOR_MULT_DOSStub_6c59 {
  strings:
    $key_6c59 = { 38 31 [2] 4c 29 [2] 0b 2b [2] 4c 3a [2] 02 36 [2] 0e 3c [2] 19 37 [2] 02 79 [2] 3f }

  condition:
    any of them
}