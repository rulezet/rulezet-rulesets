rule TTP_XOR_MULT_DOSStub_35f7 {
  strings:
    $key_35f7 = { 61 9f [2] 15 87 [2] 52 85 [2] 15 94 [2] 5b 98 [2] 57 92 [2] 40 99 [2] 5b d7 [2] 66 }

  condition:
    any of them
}