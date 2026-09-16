rule TTP_XOR_MULT_DOSStub_1944 {
  strings:
    $key_1944 = { 4d 2c [2] 39 34 [2] 7e 36 [2] 39 27 [2] 77 2b [2] 7b 21 [2] 6c 2a [2] 77 64 [2] 4a }

  condition:
    any of them
}