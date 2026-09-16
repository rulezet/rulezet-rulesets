rule TTP_XOR_MULT_DOSStub_3249 {
  strings:
    $key_3249 = { 66 21 [2] 12 39 [2] 55 3b [2] 12 2a [2] 5c 26 [2] 50 2c [2] 47 27 [2] 5c 69 [2] 61 }

  condition:
    any of them
}