rule TTP_XOR_MULT_DOSStub_d400 {
  strings:
    $key_d400 = { 80 68 [2] f4 70 [2] b3 72 [2] f4 63 [2] ba 6f [2] b6 65 [2] a1 6e [2] ba 20 [2] 87 }

  condition:
    any of them
}