rule TTP_XOR_MULT_DOSStub_5c43 {
  strings:
    $key_5c43 = { 08 2b [2] 7c 33 [2] 3b 31 [2] 7c 20 [2] 32 2c [2] 3e 26 [2] 29 2d [2] 32 63 [2] 0f }

  condition:
    any of them
}