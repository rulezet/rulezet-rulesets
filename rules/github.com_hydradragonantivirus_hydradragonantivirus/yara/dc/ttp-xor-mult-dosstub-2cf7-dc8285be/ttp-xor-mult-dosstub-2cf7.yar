rule TTP_XOR_MULT_DOSStub_2cf7 {
  strings:
    $key_2cf7 = { 78 9f [2] 0c 87 [2] 4b 85 [2] 0c 94 [2] 42 98 [2] 4e 92 [2] 59 99 [2] 42 d7 [2] 7f }

  condition:
    any of them
}