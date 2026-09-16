rule TTP_XOR_MULT_DOSStub_2002 {
  strings:
    $key_2002 = { 74 6a [2] 00 72 [2] 47 70 [2] 00 61 [2] 4e 6d [2] 42 67 [2] 55 6c [2] 4e 22 [2] 73 }

  condition:
    any of them
}