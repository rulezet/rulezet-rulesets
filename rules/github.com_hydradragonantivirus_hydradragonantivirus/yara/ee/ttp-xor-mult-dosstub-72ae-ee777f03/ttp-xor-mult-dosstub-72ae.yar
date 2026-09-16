rule TTP_XOR_MULT_DOSStub_72ae {
  strings:
    $key_72ae = { 26 c6 [2] 52 de [2] 15 dc [2] 52 cd [2] 1c c1 [2] 10 cb [2] 07 c0 [2] 1c 8e [2] 21 }

  condition:
    any of them
}