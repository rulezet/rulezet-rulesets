rule TTP_XOR_MULT_DOSStub_6362 {
  strings:
    $key_6362 = { 37 0a [2] 43 12 [2] 04 10 [2] 43 01 [2] 0d 0d [2] 01 07 [2] 16 0c [2] 0d 42 [2] 30 }

  condition:
    any of them
}