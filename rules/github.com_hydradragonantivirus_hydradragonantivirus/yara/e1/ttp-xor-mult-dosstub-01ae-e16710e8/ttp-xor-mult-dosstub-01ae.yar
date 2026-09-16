rule TTP_XOR_MULT_DOSStub_01ae {
  strings:
    $key_01ae = { 55 c6 [2] 21 de [2] 66 dc [2] 21 cd [2] 6f c1 [2] 63 cb [2] 74 c0 [2] 6f 8e [2] 52 }

  condition:
    any of them
}