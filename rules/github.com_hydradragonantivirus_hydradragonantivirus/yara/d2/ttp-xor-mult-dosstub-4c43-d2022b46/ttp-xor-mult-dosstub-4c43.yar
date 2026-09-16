rule TTP_XOR_MULT_DOSStub_4c43 {
  strings:
    $key_4c43 = { 18 2b [2] 6c 33 [2] 2b 31 [2] 6c 20 [2] 22 2c [2] 2e 26 [2] 39 2d [2] 22 63 [2] 1f }

  condition:
    any of them
}