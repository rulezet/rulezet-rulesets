rule TTP_XOR_MULT_DOSStub_09f7 {
  strings:
    $key_09f7 = { 5d 9f [2] 29 87 [2] 6e 85 [2] 29 94 [2] 67 98 [2] 6b 92 [2] 7c 99 [2] 67 d7 [2] 5a }

  condition:
    any of them
}