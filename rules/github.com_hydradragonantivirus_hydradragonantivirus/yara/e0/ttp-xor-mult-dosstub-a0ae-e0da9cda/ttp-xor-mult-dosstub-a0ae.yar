rule TTP_XOR_MULT_DOSStub_a0ae {
  strings:
    $key_a0ae = { f4 c6 [2] 80 de [2] c7 dc [2] 80 cd [2] ce c1 [2] c2 cb [2] d5 c0 [2] ce 8e [2] f3 }

  condition:
    any of them
}