rule TTP_XOR_MULT_DOSStub_00ae {
  strings:
    $key_00ae = { 54 c6 [2] 20 de [2] 67 dc [2] 20 cd [2] 6e c1 [2] 62 cb [2] 75 c0 [2] 6e 8e [2] 53 }

  condition:
    any of them
}