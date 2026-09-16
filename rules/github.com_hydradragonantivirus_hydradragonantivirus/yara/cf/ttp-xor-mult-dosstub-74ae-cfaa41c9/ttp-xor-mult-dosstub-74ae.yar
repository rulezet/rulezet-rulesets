rule TTP_XOR_MULT_DOSStub_74ae {
  strings:
    $key_74ae = { 20 c6 [2] 54 de [2] 13 dc [2] 54 cd [2] 1a c1 [2] 16 cb [2] 01 c0 [2] 1a 8e [2] 27 }

  condition:
    any of them
}