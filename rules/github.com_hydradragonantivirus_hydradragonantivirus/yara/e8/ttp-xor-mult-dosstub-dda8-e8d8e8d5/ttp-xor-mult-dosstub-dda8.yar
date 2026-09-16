rule TTP_XOR_MULT_DOSStub_dda8 {
  strings:
    $key_dda8 = { 89 c0 [2] fd d8 [2] ba da [2] fd cb [2] b3 c7 [2] bf cd [2] a8 c6 [2] b3 88 [2] 8e }

  condition:
    any of them
}