rule TTP_XOR_MULT_DOSStub_0762 {
  strings:
    $key_0762 = { 53 0a [2] 27 12 [2] 60 10 [2] 27 01 [2] 69 0d [2] 65 07 [2] 72 0c [2] 69 42 [2] 54 }

  condition:
    any of them
}