rule TTP_XOR_MULT_DOSStub_b6ae {
  strings:
    $key_b6ae = { e2 c6 [2] 96 de [2] d1 dc [2] 96 cd [2] d8 c1 [2] d4 cb [2] c3 c0 [2] d8 8e [2] e5 }

  condition:
    any of them
}