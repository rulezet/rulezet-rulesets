rule TTP_XOR_MULT_DOSStub_36e7 {
  strings:
    $key_36e7 = { 62 8f [2] 16 97 [2] 51 95 [2] 16 84 [2] 58 88 [2] 54 82 [2] 43 89 [2] 58 c7 [2] 65 }

  condition:
    any of them
}