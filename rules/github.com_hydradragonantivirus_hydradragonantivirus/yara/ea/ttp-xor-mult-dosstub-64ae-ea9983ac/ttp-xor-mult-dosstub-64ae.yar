rule TTP_XOR_MULT_DOSStub_64ae {
  strings:
    $key_64ae = { 30 c6 [2] 44 de [2] 03 dc [2] 44 cd [2] 0a c1 [2] 06 cb [2] 11 c0 [2] 0a 8e [2] 37 }

  condition:
    any of them
}