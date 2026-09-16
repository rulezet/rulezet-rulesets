rule TTP_XOR_MULT_DOSStub_2143 {
  strings:
    $key_2143 = { 75 2b [2] 01 33 [2] 46 31 [2] 01 20 [2] 4f 2c [2] 43 26 [2] 54 2d [2] 4f 63 [2] 72 }

  condition:
    any of them
}