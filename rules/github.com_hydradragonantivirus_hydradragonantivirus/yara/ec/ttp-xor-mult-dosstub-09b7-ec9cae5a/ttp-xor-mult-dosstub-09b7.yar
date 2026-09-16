rule TTP_XOR_MULT_DOSStub_09b7 {
  strings:
    $key_09b7 = { 5d df [2] 29 c7 [2] 6e c5 [2] 29 d4 [2] 67 d8 [2] 6b d2 [2] 7c d9 [2] 67 97 [2] 5a }

  condition:
    any of them
}