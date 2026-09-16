rule TTP_XOR_MULT_DOSStub_2064 {
  strings:
    $key_2064 = { 74 0c [2] 00 14 [2] 47 16 [2] 00 07 [2] 4e 0b [2] 42 01 [2] 55 0a [2] 4e 44 [2] 73 }

  condition:
    any of them
}