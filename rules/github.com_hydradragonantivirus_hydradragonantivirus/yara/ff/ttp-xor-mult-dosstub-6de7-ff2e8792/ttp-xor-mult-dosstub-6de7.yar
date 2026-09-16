rule TTP_XOR_MULT_DOSStub_6de7 {
  strings:
    $key_6de7 = { 39 8f [2] 4d 97 [2] 0a 95 [2] 4d 84 [2] 03 88 [2] 0f 82 [2] 18 89 [2] 03 c7 [2] 3e }

  condition:
    any of them
}