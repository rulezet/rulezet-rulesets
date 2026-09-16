rule TTP_XOR_MULT_DOSStub_09e7 {
  strings:
    $key_09e7 = { 5d 8f [2] 29 97 [2] 6e 95 [2] 29 84 [2] 67 88 [2] 6b 82 [2] 7c 89 [2] 67 c7 [2] 5a }

  condition:
    any of them
}