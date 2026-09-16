rule TTP_XOR_MULT_DOSStub_1043 {
  strings:
    $key_1043 = { 44 2b [2] 30 33 [2] 77 31 [2] 30 20 [2] 7e 2c [2] 72 26 [2] 65 2d [2] 7e 63 [2] 43 }

  condition:
    any of them
}