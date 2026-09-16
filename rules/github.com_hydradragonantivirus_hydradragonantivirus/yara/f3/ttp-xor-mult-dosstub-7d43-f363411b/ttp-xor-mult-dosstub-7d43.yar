rule TTP_XOR_MULT_DOSStub_7d43 {
  strings:
    $key_7d43 = { 29 2b [2] 5d 33 [2] 1a 31 [2] 5d 20 [2] 13 2c [2] 1f 26 [2] 08 2d [2] 13 63 [2] 2e }

  condition:
    any of them
}