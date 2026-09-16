rule TTP_XOR_MULT_DOSStub_51ae {
  strings:
    $key_51ae = { 05 c6 [2] 71 de [2] 36 dc [2] 71 cd [2] 3f c1 [2] 33 cb [2] 24 c0 [2] 3f 8e [2] 02 }

  condition:
    any of them
}