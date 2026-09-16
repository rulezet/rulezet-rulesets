rule TTP_XOR_MULT_DOSStub_6763 {
  strings:
    $key_6763 = { 33 0b [2] 47 13 [2] 00 11 [2] 47 00 [2] 09 0c [2] 05 06 [2] 12 0d [2] 09 43 [2] 34 }

  condition:
    any of them
}