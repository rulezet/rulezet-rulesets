rule TTP_XOR_MULT_DOSStub_f7ae {
  strings:
    $key_f7ae = { a3 c6 [2] d7 de [2] 90 dc [2] d7 cd [2] 99 c1 [2] 95 cb [2] 82 c0 [2] 99 8e [2] a4 }

  condition:
    any of them
}