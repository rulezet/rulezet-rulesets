rule TTP_XOR_MULT_DOSStub_d4f4 {
  strings:
    $key_d4f4 = { 80 9c [2] f4 84 [2] b3 86 [2] f4 97 [2] ba 9b [2] b6 91 [2] a1 9a [2] ba d4 [2] 87 }

  condition:
    any of them
}