rule TTP_XOR_MULT_DOSStub_42ae {
  strings:
    $key_42ae = { 16 c6 [2] 62 de [2] 25 dc [2] 62 cd [2] 2c c1 [2] 20 cb [2] 37 c0 [2] 2c 8e [2] 11 }

  condition:
    any of them
}