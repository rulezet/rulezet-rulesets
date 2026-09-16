rule TTP_XOR_MULT_DOSStub_2de6 {
  strings:
    $key_2de6 = { 79 8e [2] 0d 96 [2] 4a 94 [2] 0d 85 [2] 43 89 [2] 4f 83 [2] 58 88 [2] 43 c6 [2] 7e }

  condition:
    any of them
}