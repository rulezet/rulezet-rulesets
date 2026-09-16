rule TTP_XOR_MULT_DOSStub_7756 {
  strings:
    $key_7756 = { 23 3e [2] 57 26 [2] 10 24 [2] 57 35 [2] 19 39 [2] 15 33 [2] 02 38 [2] 19 76 [2] 24 }

  condition:
    any of them
}