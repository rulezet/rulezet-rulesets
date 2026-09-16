rule TTP_XOR_MULT_DOSStub_2065 {
  strings:
    $key_2065 = { 74 0d [2] 00 15 [2] 47 17 [2] 00 06 [2] 4e 0a [2] 42 00 [2] 55 0b [2] 4e 45 [2] 73 }

  condition:
    any of them
}