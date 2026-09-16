rule TTP_XOR_MULT_DOSStub_6241 {
  strings:
    $key_6241 = { 36 29 [2] 42 31 [2] 05 33 [2] 42 22 [2] 0c 2e [2] 00 24 [2] 17 2f [2] 0c 61 [2] 31 }

  condition:
    any of them
}