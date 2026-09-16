rule TTP_XOR_MULT_DOSStub_d418 {
  strings:
    $key_d418 = { 80 70 [2] f4 68 [2] b3 6a [2] f4 7b [2] ba 77 [2] b6 7d [2] a1 76 [2] ba 38 [2] 87 }

  condition:
    any of them
}