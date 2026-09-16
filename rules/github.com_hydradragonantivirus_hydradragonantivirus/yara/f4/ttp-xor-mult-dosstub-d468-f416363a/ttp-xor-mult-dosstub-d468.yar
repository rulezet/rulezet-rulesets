rule TTP_XOR_MULT_DOSStub_d468 {
  strings:
    $key_d468 = { 80 00 [2] f4 18 [2] b3 1a [2] f4 0b [2] ba 07 [2] b6 0d [2] a1 06 [2] ba 48 [2] 87 }

  condition:
    any of them
}