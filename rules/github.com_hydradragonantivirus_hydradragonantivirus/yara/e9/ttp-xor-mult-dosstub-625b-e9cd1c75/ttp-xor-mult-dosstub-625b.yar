rule TTP_XOR_MULT_DOSStub_625b {
  strings:
    $key_625b = { 36 33 [2] 42 2b [2] 05 29 [2] 42 38 [2] 0c 34 [2] 00 3e [2] 17 35 [2] 0c 7b [2] 31 }

  condition:
    any of them
}