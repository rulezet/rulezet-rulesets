rule TTP_XOR_MULT_DOSStub_4d43 {
  strings:
    $key_4d43 = { 19 2b [2] 6d 33 [2] 2a 31 [2] 6d 20 [2] 23 2c [2] 2f 26 [2] 38 2d [2] 23 63 [2] 1e }

  condition:
    any of them
}