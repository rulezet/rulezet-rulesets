rule TTP_XOR_MULT_DOSStub_7762 {
  strings:
    $key_7762 = { 23 0a [2] 57 12 [2] 10 10 [2] 57 01 [2] 19 0d [2] 15 07 [2] 02 0c [2] 19 42 [2] 24 }

  condition:
    any of them
}