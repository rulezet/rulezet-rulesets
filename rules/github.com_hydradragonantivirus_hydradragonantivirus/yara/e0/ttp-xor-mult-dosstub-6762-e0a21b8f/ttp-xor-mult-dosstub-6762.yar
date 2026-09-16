rule TTP_XOR_MULT_DOSStub_6762 {
  strings:
    $key_6762 = { 33 0a [2] 47 12 [2] 00 10 [2] 47 01 [2] 09 0d [2] 05 07 [2] 12 0c [2] 09 42 [2] 34 }

  condition:
    any of them
}