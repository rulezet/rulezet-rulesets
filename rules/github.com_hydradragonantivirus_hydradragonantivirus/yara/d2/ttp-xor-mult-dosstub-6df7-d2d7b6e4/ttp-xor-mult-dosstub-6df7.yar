rule TTP_XOR_MULT_DOSStub_6df7 {
  strings:
    $key_6df7 = { 39 9f [2] 4d 87 [2] 0a 85 [2] 4d 94 [2] 03 98 [2] 0f 92 [2] 18 99 [2] 03 d7 [2] 3e }

  condition:
    any of them
}