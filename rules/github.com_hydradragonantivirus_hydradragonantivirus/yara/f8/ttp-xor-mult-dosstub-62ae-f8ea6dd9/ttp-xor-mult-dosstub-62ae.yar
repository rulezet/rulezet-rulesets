rule TTP_XOR_MULT_DOSStub_62ae {
  strings:
    $key_62ae = { 36 c6 [2] 42 de [2] 05 dc [2] 42 cd [2] 0c c1 [2] 00 cb [2] 17 c0 [2] 0c 8e [2] 31 }

  condition:
    any of them
}