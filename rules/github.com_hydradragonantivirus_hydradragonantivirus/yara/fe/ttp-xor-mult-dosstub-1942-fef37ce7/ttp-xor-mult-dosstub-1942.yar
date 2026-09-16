rule TTP_XOR_MULT_DOSStub_1942 {
  strings:
    $key_1942 = { 4d 2a [2] 39 32 [2] 7e 30 [2] 39 21 [2] 77 2d [2] 7b 27 [2] 6c 2c [2] 77 62 [2] 4a }

  condition:
    any of them
}