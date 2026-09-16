rule TTP_XOR_MULT_DOSStub_0a44 {
  strings:
    $key_0a44 = { 5e 2c [2] 2a 34 [2] 6d 36 [2] 2a 27 [2] 64 2b [2] 68 21 [2] 7f 2a [2] 64 64 [2] 59 }

  condition:
    any of them
}