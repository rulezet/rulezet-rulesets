rule TTP_XOR_MULT_DOSStub_1443 {
  strings:
    $key_1443 = { 40 2b [2] 34 33 [2] 73 31 [2] 34 20 [2] 7a 2c [2] 76 26 [2] 61 2d [2] 7a 63 [2] 47 }

  condition:
    any of them
}