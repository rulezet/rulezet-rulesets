rule TTP_XOR_MULT_DOSStub_f4ae {
  strings:
    $key_f4ae = { a0 c6 [2] d4 de [2] 93 dc [2] d4 cd [2] 9a c1 [2] 96 cb [2] 81 c0 [2] 9a 8e [2] a7 }

  condition:
    any of them
}