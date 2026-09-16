rule TTP_XOR_MULT_DOSStub_5075 {
  strings:
    $key_5075 = { 04 1d [2] 70 05 [2] 37 07 [2] 70 16 [2] 3e 1a [2] 32 10 [2] 25 1b [2] 3e 55 [2] 03 }

  condition:
    any of them
}