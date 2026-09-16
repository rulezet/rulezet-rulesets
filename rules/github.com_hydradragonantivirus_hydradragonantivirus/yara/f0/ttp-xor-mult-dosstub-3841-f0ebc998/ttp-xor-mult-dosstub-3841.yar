rule TTP_XOR_MULT_DOSStub_3841 {
  strings:
    $key_3841 = { 6c 29 [2] 18 31 [2] 5f 33 [2] 18 22 [2] 56 2e [2] 5a 24 [2] 4d 2f [2] 56 61 [2] 6b }

  condition:
    any of them
}