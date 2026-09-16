rule TTP_XOR_MULT_DOSStub_d467 {
  strings:
    $key_d467 = { 80 0f [2] f4 17 [2] b3 15 [2] f4 04 [2] ba 08 [2] b6 02 [2] a1 09 [2] ba 47 [2] 87 }

  condition:
    any of them
}