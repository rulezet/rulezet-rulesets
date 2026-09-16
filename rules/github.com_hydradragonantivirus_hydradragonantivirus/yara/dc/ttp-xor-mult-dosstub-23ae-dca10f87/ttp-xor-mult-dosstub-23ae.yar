rule TTP_XOR_MULT_DOSStub_23ae {
  strings:
    $key_23ae = { 77 c6 [2] 03 de [2] 44 dc [2] 03 cd [2] 4d c1 [2] 41 cb [2] 56 c0 [2] 4d 8e [2] 70 }

  condition:
    any of them
}