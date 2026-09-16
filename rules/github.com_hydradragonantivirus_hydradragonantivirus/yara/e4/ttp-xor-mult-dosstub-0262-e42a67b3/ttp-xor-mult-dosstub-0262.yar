rule TTP_XOR_MULT_DOSStub_0262 {
  strings:
    $key_0262 = { 56 0a [2] 22 12 [2] 65 10 [2] 22 01 [2] 6c 0d [2] 60 07 [2] 77 0c [2] 6c 42 [2] 51 }

  condition:
    any of them
}