rule TTP_XOR_MULT_DOSStub_50ae {
  strings:
    $key_50ae = { 04 c6 [2] 70 de [2] 37 dc [2] 70 cd [2] 3e c1 [2] 32 cb [2] 25 c0 [2] 3e 8e [2] 03 }

  condition:
    any of them
}