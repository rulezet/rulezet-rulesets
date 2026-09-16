rule TTP_XOR_MULT_DOSStub_d4f8 {
  strings:
    $key_d4f8 = { 80 90 [2] f4 88 [2] b3 8a [2] f4 9b [2] ba 97 [2] b6 9d [2] a1 96 [2] ba d8 [2] 87 }

  condition:
    any of them
}