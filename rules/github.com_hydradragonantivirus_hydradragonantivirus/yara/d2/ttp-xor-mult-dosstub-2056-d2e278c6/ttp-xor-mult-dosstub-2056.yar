rule TTP_XOR_MULT_DOSStub_2056 {
  strings:
    $key_2056 = { 74 3e [2] 00 26 [2] 47 24 [2] 00 35 [2] 4e 39 [2] 42 33 [2] 55 38 [2] 4e 76 [2] 73 }

  condition:
    any of them
}