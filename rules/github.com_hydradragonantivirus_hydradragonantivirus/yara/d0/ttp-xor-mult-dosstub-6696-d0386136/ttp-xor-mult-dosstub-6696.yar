rule TTP_XOR_MULT_DOSStub_6696 {
  strings:
    $key_6696 = { 32 fe [2] 46 e6 [2] 01 e4 [2] 46 f5 [2] 08 f9 [2] 04 f3 [2] 13 f8 [2] 08 b6 [2] 35 }

  condition:
    any of them
}