rule TTP_XOR_MULT_DOSStub_d4f2 {
  strings:
    $key_d4f2 = { 80 9a [2] f4 82 [2] b3 80 [2] f4 91 [2] ba 9d [2] b6 97 [2] a1 9c [2] ba d2 [2] 87 }

  condition:
    any of them
}