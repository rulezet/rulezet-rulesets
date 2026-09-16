rule TTP_XOR_MULT_DOSStub_d867 {
  strings:
    $key_d867 = { 8c 0f [2] f8 17 [2] bf 15 [2] f8 04 [2] b6 08 [2] ba 02 [2] ad 09 [2] b6 47 [2] 8b }

  condition:
    any of them
}