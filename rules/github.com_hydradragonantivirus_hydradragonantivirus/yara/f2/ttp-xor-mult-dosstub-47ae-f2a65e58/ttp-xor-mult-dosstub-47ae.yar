rule TTP_XOR_MULT_DOSStub_47ae {
  strings:
    $key_47ae = { 13 c6 [2] 67 de [2] 20 dc [2] 67 cd [2] 29 c1 [2] 25 cb [2] 32 c0 [2] 29 8e [2] 14 }

  condition:
    any of them
}