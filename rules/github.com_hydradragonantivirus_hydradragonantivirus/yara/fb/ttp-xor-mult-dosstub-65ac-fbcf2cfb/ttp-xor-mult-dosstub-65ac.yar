rule TTP_XOR_MULT_DOSStub_65ac {
  strings:
    $key_65ac = { 31 c4 [2] 45 dc [2] 02 de [2] 45 cf [2] 0b c3 [2] 07 c9 [2] 10 c2 [2] 0b 8c [2] 36 }

  condition:
    any of them
}