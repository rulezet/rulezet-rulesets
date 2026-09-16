rule TTP_XOR_MULT_DOSStub_3562 {
  strings:
    $key_3562 = { 61 0a [2] 15 12 [2] 52 10 [2] 15 01 [2] 5b 0d [2] 57 07 [2] 40 0c [2] 5b 42 [2] 66 }

  condition:
    any of them
}