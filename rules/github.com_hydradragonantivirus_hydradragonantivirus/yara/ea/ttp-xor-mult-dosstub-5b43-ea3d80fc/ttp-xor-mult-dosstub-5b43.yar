rule TTP_XOR_MULT_DOSStub_5b43 {
  strings:
    $key_5b43 = { 0f 2b [2] 7b 33 [2] 3c 31 [2] 7b 20 [2] 35 2c [2] 39 26 [2] 2e 2d [2] 35 63 [2] 08 }

  condition:
    any of them
}