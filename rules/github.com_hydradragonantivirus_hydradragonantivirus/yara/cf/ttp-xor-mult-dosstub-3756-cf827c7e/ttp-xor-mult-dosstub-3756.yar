rule TTP_XOR_MULT_DOSStub_3756 {
  strings:
    $key_3756 = { 63 3e [2] 17 26 [2] 50 24 [2] 17 35 [2] 59 39 [2] 55 33 [2] 42 38 [2] 59 76 [2] 64 }

  condition:
    any of them
}