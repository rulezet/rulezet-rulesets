rule TTP_XOR_MULT_DOSStub_6bf7 {
  strings:
    $key_6bf7 = { 3f 9f [2] 4b 87 [2] 0c 85 [2] 4b 94 [2] 05 98 [2] 09 92 [2] 1e 99 [2] 05 d7 [2] 38 }

  condition:
    any of them
}