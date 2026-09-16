rule TTP_XOR_MULT_DOSStub_7562 {
  strings:
    $key_7562 = { 21 0a [2] 55 12 [2] 12 10 [2] 55 01 [2] 1b 0d [2] 17 07 [2] 00 0c [2] 1b 42 [2] 26 }

  condition:
    any of them
}