rule TTP_XOR_MULT_DOSStub_6841 {
  strings:
    $key_6841 = { 3c 29 [2] 48 31 [2] 0f 33 [2] 48 22 [2] 06 2e [2] 0a 24 [2] 1d 2f [2] 06 61 [2] 3b }

  condition:
    any of them
}