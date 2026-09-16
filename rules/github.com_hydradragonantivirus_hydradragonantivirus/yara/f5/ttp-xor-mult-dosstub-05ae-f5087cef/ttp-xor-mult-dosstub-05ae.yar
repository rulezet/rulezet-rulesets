rule TTP_XOR_MULT_DOSStub_05ae {
  strings:
    $key_05ae = { 51 c6 [2] 25 de [2] 62 dc [2] 25 cd [2] 6b c1 [2] 67 cb [2] 70 c0 [2] 6b 8e [2] 56 }

  condition:
    any of them
}