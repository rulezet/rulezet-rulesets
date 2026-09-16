rule TTP_XOR_MULT_DOSStub_0941 {
  strings:
    $key_0941 = { 5d 29 [2] 29 31 [2] 6e 33 [2] 29 22 [2] 67 2e [2] 6b 24 [2] 7c 2f [2] 67 61 [2] 5a }

  condition:
    any of them
}