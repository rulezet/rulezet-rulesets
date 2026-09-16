rule TTP_XOR_MULT_DOSStub_4213 {
  strings:
    $key_4213 = { 16 7b [2] 62 63 [2] 25 61 [2] 62 70 [2] 2c 7c [2] 20 76 [2] 37 7d [2] 2c 33 [2] 11 }

  condition:
    any of them
}