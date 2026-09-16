rule TTP_XOR_MULT_DOSStub_60ae {
  strings:
    $key_60ae = { 34 c6 [2] 40 de [2] 07 dc [2] 40 cd [2] 0e c1 [2] 02 cb [2] 15 c0 [2] 0e 8e [2] 33 }

  condition:
    any of them
}