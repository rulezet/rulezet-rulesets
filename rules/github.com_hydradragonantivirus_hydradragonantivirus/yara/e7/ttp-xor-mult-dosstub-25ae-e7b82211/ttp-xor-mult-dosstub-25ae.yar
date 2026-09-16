rule TTP_XOR_MULT_DOSStub_25ae {
  strings:
    $key_25ae = { 71 c6 [2] 05 de [2] 42 dc [2] 05 cd [2] 4b c1 [2] 47 cb [2] 50 c0 [2] 4b 8e [2] 76 }

  condition:
    any of them
}