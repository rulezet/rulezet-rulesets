rule TTP_XOR_MULT_DOSStub_2144 {
  strings:
    $key_2144 = { 75 2c [2] 01 34 [2] 46 36 [2] 01 27 [2] 4f 2b [2] 43 21 [2] 54 2a [2] 4f 64 [2] 72 }

  condition:
    any of them
}