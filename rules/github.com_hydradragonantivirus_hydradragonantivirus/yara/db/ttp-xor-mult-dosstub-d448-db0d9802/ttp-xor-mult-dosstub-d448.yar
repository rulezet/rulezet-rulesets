rule TTP_XOR_MULT_DOSStub_d448 {
  strings:
    $key_d448 = { 80 20 [2] f4 38 [2] b3 3a [2] f4 2b [2] ba 27 [2] b6 2d [2] a1 26 [2] ba 68 [2] 87 }

  condition:
    any of them
}