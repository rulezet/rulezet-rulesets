rule TTP_XOR_MULT_DOSStub_68e7 {
  strings:
    $key_68e7 = { 3c 8f [2] 48 97 [2] 0f 95 [2] 48 84 [2] 06 88 [2] 0a 82 [2] 1d 89 [2] 06 c7 [2] 3b }

  condition:
    any of them
}