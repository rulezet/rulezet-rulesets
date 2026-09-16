rule TTP_XOR_MULT_DOSStub_4763 {
  strings:
    $key_4763 = { 13 0b [2] 67 13 [2] 20 11 [2] 67 00 [2] 29 0c [2] 25 06 [2] 32 0d [2] 29 43 [2] 14 }

  condition:
    any of them
}