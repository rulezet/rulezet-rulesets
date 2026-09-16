rule TTP_XOR_MULT_DOSStub_4062 {
  strings:
    $key_4062 = { 14 0a [2] 60 12 [2] 27 10 [2] 60 01 [2] 2e 0d [2] 22 07 [2] 35 0c [2] 2e 42 [2] 13 }

  condition:
    any of them
}