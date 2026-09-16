rule TTP_XOR_MULT_DOSStub_28f7 {
  strings:
    $key_28f7 = { 7c 9f [2] 08 87 [2] 4f 85 [2] 08 94 [2] 46 98 [2] 4a 92 [2] 5d 99 [2] 46 d7 [2] 7b }

  condition:
    any of them
}