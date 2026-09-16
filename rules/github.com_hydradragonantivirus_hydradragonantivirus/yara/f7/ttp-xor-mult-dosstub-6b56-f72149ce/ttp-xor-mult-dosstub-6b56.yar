rule TTP_XOR_MULT_DOSStub_6b56 {
  strings:
    $key_6b56 = { 3f 3e [2] 4b 26 [2] 0c 24 [2] 4b 35 [2] 05 39 [2] 09 33 [2] 1e 38 [2] 05 76 [2] 38 }

  condition:
    any of them
}