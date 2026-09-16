rule TTP_XOR_MULT_DOSStub_4443 {
  strings:
    $key_4443 = { 10 2b [2] 64 33 [2] 23 31 [2] 64 20 [2] 2a 2c [2] 26 26 [2] 31 2d [2] 2a 63 [2] 17 }

  condition:
    any of them
}