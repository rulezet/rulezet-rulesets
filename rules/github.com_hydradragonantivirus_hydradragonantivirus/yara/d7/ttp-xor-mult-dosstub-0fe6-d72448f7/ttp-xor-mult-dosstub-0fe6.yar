rule TTP_XOR_MULT_DOSStub_0fe6 {
  strings:
    $key_0fe6 = { 5b 8e [2] 2f 96 [2] 68 94 [2] 2f 85 [2] 61 89 [2] 6d 83 [2] 7a 88 [2] 61 c6 [2] 5c }

  condition:
    any of them
}