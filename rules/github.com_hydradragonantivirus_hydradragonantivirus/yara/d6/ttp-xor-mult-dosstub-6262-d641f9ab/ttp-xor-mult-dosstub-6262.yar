rule TTP_XOR_MULT_DOSStub_6262 {
  strings:
    $key_6262 = { 36 0a [2] 42 12 [2] 05 10 [2] 42 01 [2] 0c 0d [2] 00 07 [2] 17 0c [2] 0c 42 [2] 31 }

  condition:
    any of them
}