rule TTP_XOR_MULT_DOSStub_6079 {
  strings:
    $key_6079 = { 34 11 [2] 40 09 [2] 07 0b [2] 40 1a [2] 0e 16 [2] 02 1c [2] 15 17 [2] 0e 59 [2] 33 }

  condition:
    any of them
}