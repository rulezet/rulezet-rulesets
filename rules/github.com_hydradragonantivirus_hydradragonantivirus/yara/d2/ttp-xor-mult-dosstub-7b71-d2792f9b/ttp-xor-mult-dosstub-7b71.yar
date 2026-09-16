rule TTP_XOR_MULT_DOSStub_7b71 {
  strings:
    $key_7b71 = { 2f 19 [2] 5b 01 [2] 1c 03 [2] 5b 12 [2] 15 1e [2] 19 14 [2] 0e 1f [2] 15 51 [2] 28 }

  condition:
    any of them
}