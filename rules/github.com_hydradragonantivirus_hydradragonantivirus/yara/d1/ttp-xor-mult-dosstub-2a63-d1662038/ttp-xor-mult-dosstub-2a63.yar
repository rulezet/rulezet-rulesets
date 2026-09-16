rule TTP_XOR_MULT_DOSStub_2a63 {
  strings:
    $key_2a63 = { 7e 0b [2] 0a 13 [2] 4d 11 [2] 0a 00 [2] 44 0c [2] 48 06 [2] 5f 0d [2] 44 43 [2] 79 }

  condition:
    any of them
}