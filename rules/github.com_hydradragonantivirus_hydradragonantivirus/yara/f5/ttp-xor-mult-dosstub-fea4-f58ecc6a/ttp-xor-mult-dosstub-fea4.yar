rule TTP_XOR_MULT_DOSStub_fea4 {
  strings:
    $key_fea4 = { aa cc [2] de d4 [2] 99 d6 [2] de c7 [2] 90 cb [2] 9c c1 [2] 8b ca [2] 90 84 [2] ad }

  condition:
    any of them
}