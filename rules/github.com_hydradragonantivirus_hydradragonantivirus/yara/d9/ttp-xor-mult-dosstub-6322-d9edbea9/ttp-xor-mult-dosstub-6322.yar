rule TTP_XOR_MULT_DOSStub_6322 {
  strings:
    $key_6322 = { 37 4a [2] 43 52 [2] 04 50 [2] 43 41 [2] 0d 4d [2] 01 47 [2] 16 4c [2] 0d 02 [2] 30 }

  condition:
    any of them
}