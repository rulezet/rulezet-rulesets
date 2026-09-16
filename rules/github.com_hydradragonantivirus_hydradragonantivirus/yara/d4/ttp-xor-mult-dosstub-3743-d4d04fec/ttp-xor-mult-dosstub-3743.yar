rule TTP_XOR_MULT_DOSStub_3743 {
  strings:
    $key_3743 = { 63 2b [2] 17 33 [2] 50 31 [2] 17 20 [2] 59 2c [2] 55 26 [2] 42 2d [2] 59 63 [2] 64 }

  condition:
    any of them
}