rule TTP_XOR_MULT_DOSStub_5235 {
  strings:
    $key_5235 = { 06 5d [2] 72 45 [2] 35 47 [2] 72 56 [2] 3c 5a [2] 30 50 [2] 27 5b [2] 3c 15 [2] 01 }

  condition:
    any of them
}