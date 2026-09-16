rule TTP_XOR_MULT_DOSStub_0841 {
  strings:
    $key_0841 = { 5c 29 [2] 28 31 [2] 6f 33 [2] 28 22 [2] 66 2e [2] 6a 24 [2] 7d 2f [2] 66 61 [2] 5b }

  condition:
    any of them
}