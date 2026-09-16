rule TTP_XOR_MULT_DOSStub_d4f5 {
  strings:
    $key_d4f5 = { 80 9d [2] f4 85 [2] b3 87 [2] f4 96 [2] ba 9a [2] b6 90 [2] a1 9b [2] ba d5 [2] 87 }

  condition:
    any of them
}