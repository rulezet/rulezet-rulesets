rule TTP_XOR_MULT_DOSStub_3173 {
  strings:
    $key_3173 = { 65 1b [2] 11 03 [2] 56 01 [2] 11 10 [2] 5f 1c [2] 53 16 [2] 44 1d [2] 5f 53 [2] 62 }

  condition:
    any of them
}