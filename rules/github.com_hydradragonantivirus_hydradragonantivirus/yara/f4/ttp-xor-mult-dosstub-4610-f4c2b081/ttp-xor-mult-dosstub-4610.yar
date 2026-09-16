rule TTP_XOR_MULT_DOSStub_4610 {
  strings:
    $key_4610 = { 12 78 [2] 66 60 [2] 21 62 [2] 66 73 [2] 28 7f [2] 24 75 [2] 33 7e [2] 28 30 [2] 15 }

  condition:
    any of them
}