rule TTP_XOR_MULT_DOSStub_efa4 {
  strings:
    $key_efa4 = { bb cc [2] cf d4 [2] 88 d6 [2] cf c7 [2] 81 cb [2] 8d c1 [2] 9a ca [2] 81 84 [2] bc }

  condition:
    any of them
}