rule TTP_XOR_MULT_DOSStub_6235 {
  strings:
    $key_6235 = { 36 5d [2] 42 45 [2] 05 47 [2] 42 56 [2] 0c 5a [2] 00 50 [2] 17 5b [2] 0c 15 [2] 31 }

  condition:
    any of them
}