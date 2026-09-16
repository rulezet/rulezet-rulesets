rule TTP_XOR_MULT_DOSStub_26ae {
  strings:
    $key_26ae = { 72 c6 [2] 06 de [2] 41 dc [2] 06 cd [2] 48 c1 [2] 44 cb [2] 53 c0 [2] 48 8e [2] 75 }

  condition:
    any of them
}