rule TTP_XOR_MULT_DOSStub_3573 {
  strings:
    $key_3573 = { 61 1b [2] 15 03 [2] 52 01 [2] 15 10 [2] 5b 1c [2] 57 16 [2] 40 1d [2] 5b 53 [2] 66 }

  condition:
    any of them
}