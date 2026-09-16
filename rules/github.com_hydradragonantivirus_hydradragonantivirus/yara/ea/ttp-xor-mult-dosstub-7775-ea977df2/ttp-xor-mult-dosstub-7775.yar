rule TTP_XOR_MULT_DOSStub_7775 {
  strings:
    $key_7775 = { 23 1d [2] 57 05 [2] 10 07 [2] 57 16 [2] 19 1a [2] 15 10 [2] 02 1b [2] 19 55 [2] 24 }

  condition:
    any of them
}