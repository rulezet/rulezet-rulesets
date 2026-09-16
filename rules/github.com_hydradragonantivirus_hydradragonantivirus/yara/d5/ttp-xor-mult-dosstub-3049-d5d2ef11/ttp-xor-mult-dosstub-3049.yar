rule TTP_XOR_MULT_DOSStub_3049 {
  strings:
    $key_3049 = { 64 21 [2] 10 39 [2] 57 3b [2] 10 2a [2] 5e 26 [2] 52 2c [2] 45 27 [2] 5e 69 [2] 63 }

  condition:
    any of them
}