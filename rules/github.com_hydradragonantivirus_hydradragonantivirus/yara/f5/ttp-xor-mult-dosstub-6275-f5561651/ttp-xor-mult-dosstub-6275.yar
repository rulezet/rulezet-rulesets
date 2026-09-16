rule TTP_XOR_MULT_DOSStub_6275 {
  strings:
    $key_6275 = { 36 1d [2] 42 05 [2] 05 07 [2] 42 16 [2] 0c 1a [2] 00 10 [2] 17 1b [2] 0c 55 [2] 31 }

  condition:
    any of them
}