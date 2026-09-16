rule TTP_XOR_MULT_DOSStub_eef7 {
  strings:
    $key_eef7 = { ba 9f [2] ce 87 [2] 89 85 [2] ce 94 [2] 80 98 [2] 8c 92 [2] 9b 99 [2] 80 d7 [2] bd }

  condition:
    any of them
}