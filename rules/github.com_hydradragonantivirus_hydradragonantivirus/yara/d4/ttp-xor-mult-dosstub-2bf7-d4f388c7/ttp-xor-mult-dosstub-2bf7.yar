rule TTP_XOR_MULT_DOSStub_2bf7 {
  strings:
    $key_2bf7 = { 7f 9f [2] 0b 87 [2] 4c 85 [2] 0b 94 [2] 45 98 [2] 49 92 [2] 5e 99 [2] 45 d7 [2] 78 }

  condition:
    any of them
}