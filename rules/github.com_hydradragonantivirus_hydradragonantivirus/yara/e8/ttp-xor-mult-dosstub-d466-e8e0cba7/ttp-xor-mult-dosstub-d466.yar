rule TTP_XOR_MULT_DOSStub_d466 {
  strings:
    $key_d466 = { 80 0e [2] f4 16 [2] b3 14 [2] f4 05 [2] ba 09 [2] b6 03 [2] a1 08 [2] ba 46 [2] 87 }

  condition:
    any of them
}