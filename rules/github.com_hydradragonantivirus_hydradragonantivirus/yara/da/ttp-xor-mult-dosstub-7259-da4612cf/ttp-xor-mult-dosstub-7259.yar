rule TTP_XOR_MULT_DOSStub_7259 {
  strings:
    $key_7259 = { 26 31 [2] 52 29 [2] 15 2b [2] 52 3a [2] 1c 36 [2] 10 3c [2] 07 37 [2] 1c 79 [2] 21 }

  condition:
    any of them
}